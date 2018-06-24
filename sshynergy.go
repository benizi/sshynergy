package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/xgb"
	"github.com/BurntSushi/xgb/randr"
	"github.com/BurntSushi/xgb/xproto"

	"github.com/benizi/termstate"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
	sshkh "golang.org/x/crypto/ssh/knownhosts"
)

func check(err error) {
	if err != nil {
		log.Panicln(err)
	}
}

func isNetErr(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*net.OpError)
	return ok
}

type options map[string]string

type section struct {
	name        string
	subsections []section
	config      options
}

func indent(by string, text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	var ret string
	for _, l := range lines {
		ret += by + l + "\n"
	}
	return ret
}

func (o options) format(indent string) string {
	var lines []string
	for k, v := range o {
		lines = append(lines, indent+k+" = "+v+"\n")
	}
	return strings.Join(lines, "")
}

func (s section) format() string {
	var lines string
	lines += "section: " + s.name + "\n"
	for _, sub := range s.subsections {
		lines += "\t" + sub.name + ":\n"
		lines += sub.config.format("\t\t")
	}
	lines += s.config.format("\t")
	lines += "end\n"
	return lines
}

func keystroke(keyhosts ...string) string {
	if len(keyhosts) == 0 {
		return "Error: empty keystroke()"
	}
	if len(keyhosts[0]) == 1 {
		keyhosts[0] = fmt.Sprintf("\\u%04x", keyhosts[0])
	}
	return fmt.Sprintf("keystroke(%s)", strings.Join(keyhosts, ","))
}

func genSynergyConf(hosts []string) []byte {
	var conf string
	screens := section{name: "screens", subsections: []section{}}
	for _, host := range hosts {
		screens.subsections = append(screens.subsections, section{name: host})
	}
	links := section{name: "links", subsections: []section{}}
	for i, host := range hosts {
		prev, next := hosts[(len(hosts)+i-1)%len(hosts)], hosts[(i+1)%len(hosts)]
		links.subsections = append(links.subsections, section{
			name: host,
			config: options{
				"left":  prev,
				"up":    prev,
				"right": next,
				"down":  next,
			},
		})
	}
	serveropts := options{
		"screenSaverSync":  "true",
		"clipboardSharing": "false",
		// forward audio play/pause keystrokes to server machine
		keystroke("AudioPause"): keystroke("AudioPause", self),
		keystroke("AudioPlay"):  keystroke("AudioPlay", self),
	}
	for _, e := range os.Environ() {
		kv := strings.SplitN(e, "=", 2)
		k, v := kv[0], kv[1]
		if strings.HasPrefix(k, "SYNERGY_OPTION") {
			for _, ckv := range strings.Split(v, ",") {
				kv := strings.SplitN(ckv, "=", 2)
				serveropts[kv[0]] = kv[1]
			}
		}
	}
	opts := section{
		name:   "options",
		config: serveropts,
	}
	for _, s := range []section{screens, links, opts} {
		conf += s.format()
	}
	return []byte(conf)
}

var self string

func parseHosts(hosts []string) []string {
	var ret []string
	addedSelf := false
	for _, arg := range hosts {
		if arg == "." {
			arg = self
			addedSelf = true
		}
		ret = append(ret, arg)
	}
	if !addedSelf {
		ret = append([]string{self}, ret...)
	}
	if len(ret) == 1 {
		ret = append(ret, "_")
	}
	return ret
}

func startWithPgid(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	check(cmd.Start())
}

func serveSynergy(hosts []string, ready chan error, restart chan bool) error {
	synergys := strings.Split("synergys -f -a 127.0.0.1 -c /dev/stdin", " ")
	args := os.Getenv("SYNERGYS_ARGS")
	if args != "" {
		synergys = append(synergys, strings.Split(args, " ")...)
	}
	log.Printf("Server commandline: %v", synergys)
	cmd := exec.Command(synergys[0], synergys[1:]...)
	stdin, err := cmd.StdinPipe()
	check(err)
	stdin.Write(genSynergyConf(hosts))
	check(stdin.Close())
	startWithPgid(cmd)
	ready <- nil
	log.Println("Local synergys pid:", cmd.Process.Pid)
	finished := make(chan error, 1)
	go func() {
		finished <- cmd.Wait()
	}()
	select {
	case again := <-restart:
		if !again {
			cmd.Process.Kill()
			return fmt.Errorf("Exit request received by serveSynergy")
		}
		return nil
	case e := <-finished:
		return e
	}
}

func getAgent() sshagent.Agent {
	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	check(err)
	return sshagent.NewClient(conn)
}

type knownhost struct {
	file    string
	hosts   []string
	pubkey  ssh.PublicKey
	comment string
}

type opensshconf struct {
	user, hostname, port string
	idfiles              []string
	knownhosts           []knownhost
	hashed               bool
	env                  map[string]bool
	remoteforwards       []string
}

func (conf opensshconf) address() string {
	port := conf.port
	if port == "" {
		port = "22"
	}
	return conf.hostname + ":" + port
}

func (conf opensshconf) signersFrom(agent sshagent.Agent) func() ([]ssh.Signer, error) {
	return func() ([]ssh.Signer, error) {
		var relevant []ssh.Signer
		okFile := map[string]bool{}
		for _, file := range conf.idfiles {
			okFile[file] = true
		}
		okPubs := map[string]bool{}
		keys, err := agent.List()
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			if okFile[key.Comment] {
				okPubs[string(key.Marshal())] = true
			}
		}
		signers, err := agent.Signers()
		if err != nil {
			return nil, err
		}
		for _, signer := range signers {
			if okPubs[string(signer.PublicKey().Marshal())] {
				relevant = append(relevant, signer)
			}
		}
		if len(relevant) > 0 {
			return relevant, nil
		}
		return signers, nil
	}
}

func (conf opensshconf) agentAuth() []ssh.AuthMethod {
	agent := getAgent()
	return []ssh.AuthMethod{ssh.PublicKeysCallback(conf.signersFrom(agent))}
}

func (conf opensshconf) dial() (*ssh.Client, error) {
	return ssh.Dial("tcp", conf.address(), &ssh.ClientConfig{
		User:            conf.user,
		Auth:            conf.agentAuth(),
		HostKeyCallback: conf.hostKeyCheck,
	})
}

func (conf opensshconf) hostKeyCheck(
	hostname string,
	remote net.Addr,
	key ssh.PublicKey,
) error {
	inhost := []string{hostname, remote.String()}
	valid := map[string]bool{}
	for _, host := range inhost {
		for _, raw := range []string{host, sshkh.Normalize(host)} {
			h := raw
			if conf.hashed {
				h = sshkh.HashHostname(raw)
			}
			valid[h] = true
		}
	}
	for _, kh := range conf.knownhosts {
		pk := kh.pubkey
		if pk.Type() != key.Type() {
			continue
		}
		wire := string(pk.Marshal())
		for _, h := range kh.hosts {
			n := sshkh.Normalize(h)
			if conf.hashed {
				n = sshkh.HashHostname(n)
			}
			if !valid[n] {
				continue
			}
			if wire != string(key.Marshal()) {
				continue
			}
			return nil
		}
	}
	return fmt.Errorf("Found no matching hostkey for [%#+v]", valid)
}

func resolveHome(file string) string {
	if strings.HasPrefix(file, "~/") {
		return os.Getenv("HOME") + file[1:len(file)]
	}
	return file
}

func (conf *opensshconf) parseKnownHosts(filenames []string) error {
	for _, file := range filenames {
		in, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}
		for {
			kind, hosts, pubkey, comment, rest, err := ssh.ParseKnownHosts(in)
			in = rest
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if kind != "" {
				continue
			}
			conf.knownhosts = append(conf.knownhosts, knownhost{
				file:    file,
				hosts:   hosts,
				pubkey:  pubkey,
				comment: comment,
			})
		}
	}
	return nil
}

func sshHostConf(host string) opensshconf {
	var conf opensshconf
	knownhostfiles := []string{}
	parsed, err := exec.Command("ssh", "-G", host).Output()
	check(err)
	scanner := bufio.NewScanner(bytes.NewReader(parsed))
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), " ", 2)
		if len(parts) < 2 {
			continue
		}
		key, val := parts[0], parts[1]
		switch key {
		case "user":
			conf.user = val
		case "hostname":
			conf.hostname = val
		case "port":
			conf.port = val
		case "identityfile":
			file := resolveHome(val)
			paths := strings.Split(file, "/")
			conf.idfiles = append(conf.idfiles, file)
			conf.idfiles = append(conf.idfiles, paths[len(paths)-1])
		case "userknownhostsfile", "globalknownhostsfile":
			for _, v := range strings.Split(val, " ") {
				knownhostfiles = append(knownhostfiles, resolveHome(v))
			}
		case "hashknownhosts":
			conf.hashed = val == "yes"
		case "sendenv":
			conf.env[val] = true
		case "remoteforward":
			conf.remoteforwards = append(conf.remoteforwards, val)
		}
	}
	check(conf.parseKnownHosts(knownhostfiles))
	return conf
}

func serveConnection(remote, local net.Conn, restart chan bool) (err error) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(remote, local)
		// remote.Channel.CloseWrite() // inaccessible
	}()
	go func() {
		defer wg.Done()
		io.Copy(local, remote)
		local.(*net.TCPConn).CloseWrite()
	}()
	finished := make(chan bool, 1)
	go func() {
		wg.Wait()
		finished <- true
	}()
	select {
	case again, ok := <-restart:
		if !ok || !again {
			err = fmt.Errorf("serveConnection got exit request")
		}
	case <-finished:
	}
	remote.Close()
	local.Close()
	return err
}

type event struct {
	xgb.Event
}

func xrandrSubscribe(events chan event) {
	x, err := xgb.NewConn()
	check(err)
	check(randr.Init(x))
	root := xproto.Setup(x).DefaultScreen(x).Root
	mask := randr.NotifyMaskScreenChange |
		randr.NotifyMaskCrtcChange |
		randr.NotifyMaskOutputChange |
		randr.NotifyMaskOutputProperty
	check(randr.SelectInputChecked(x, root, uint16(mask)).Check())

	go func() {
		for {
			ev, err := x.WaitForEvent()
			if err != nil {
				log.Println("X11 error", err)
			} else {
				events <- event{ev}
			}
		}
	}()
}

func forwardRemote(conn *ssh.Client, restart chan bool) error {
	listener, err := conn.Listen("tcp", "127.0.0.1:24800")
	if isNetErr(err) {
		log.Println("ERR", err)
		log.Printf("ERR type %t", err)
		return err
	}
	check(err)
	defer listener.Close()

	for {
		remote, err := listener.Accept()
		if err == io.EOF {
			return err
		} else if err != nil {
			log.Println(err)
			return err
		}
		local, err := net.Dial("tcp", "localhost:24800")
		if err != nil {
			log.Println(err)
			continue
		}
		err = serveConnection(remote, local, restart)
		if err != nil {
			return err
		}
	}

	return nil
}

func runSynergyOn(conn *ssh.Client, host string, restart chan bool) error {
	sess, err := conn.NewSession()
	if isNetErr(err) {
		return nil
	}
	check(err)
	defer sess.Close()
	sep := ""
	args := os.Getenv("SYNERGYC_ARGS")
	if args != "" {
		sep = " "
	}
	cmd := fmt.Sprintf("synergyc -1 -f -n %s%s%s localhost", host, sep, args)
	log.Printf("Client commandline: %s", cmd)
	err = sess.Start(cmd)
	if err != nil {
		log.Printf("Error running synergyc on %s", host)
		log.Println(err)
		time.Sleep(time.Second)
		return err
	}
	log.Println("Started synergyc on", host)

	finished := make(chan error, 1)
	go func() {
		finished <- sess.Wait()
	}()

	select {
	case again, ok := <-restart:
		sess.Close()
		if again && ok {
			log.Print("runSynergyOn received restart=true")
			return nil
		}
		return fmt.Errorf("runSynergyOn received exit request")
	case e := <-finished:
		return e
	}
}

func runLocal(hosts []string, restarter *restartMux, wg *sync.WaitGroup) {
	wg.Add(1)
	ready := make(chan error, 1)
	go func() {
		defer wg.Done()
		for {
			err := serveSynergy(hosts, ready, restarter.addOutput(self))
			if err != nil {
				log.Println("Error returned from serveSynergy:", err)
				return
			}
		}
	}()
	check(<-ready)
}

func forwardRemotePort(conn *ssh.Client, host string, restart chan bool) error {
	log.Println("Forwarding remote port for", host)
	err := forwardRemote(conn, restart)
	if isNetErr(err) {
		log.Println("Net error forwarding:", err)
		log.Println("Bailing to restart", host)
	} else if err != nil {
		log.Println("Error forwarding remote:", err)
		time.Sleep(time.Second)
	}
	return err
}

func runRemoteLoop(host string, parsed opensshconf, restart chan bool) error {
	conn, err := parsed.dial()
	if isNetErr(err) {
		return err
	}
	check(err)
	defer conn.Close()

	forwardRestart := make(chan bool, 1)
	forwardDone := make(chan error, 1)
	go func() {
		for {
			err := forwardRemotePort(conn, host, forwardRestart)
			go func() {
				forwardDone <- err
			}()
			if err != nil {
				log.Print("Error running port forward: %v", err)
				return
			}
		}
	}()

	synergyRestart := make(chan bool, 1)
	synergyDone := make(chan error, 1)
	go func() {
		for {
			err := runSynergyOn(conn, host, synergyRestart)
			go func() {
				synergyDone <- err
			}()
			if err != nil {
				log.Print("Error running Synergyc: %v", err)
				return
			}
		}
	}()

	for {
		select {
		case err, ok := <-forwardDone:
			if !ok || err != nil {
				go func() {
					synergyRestart <- false
				}()
				if err == nil {
					err = fmt.Errorf("Error receiving from forwardDone")
				}
				return err
			}
		case err, ok := <-synergyDone:
			if !ok || err != nil {
				go func() {
					forwardRestart <- false
				}()
				if err == nil {
					err = fmt.Errorf("Error receiving from synergyDone")
				}
				return err
			}
		case again, ok := <-restart:
			go func() {
				forwardRestart <- again
			}()
			go func() {
				synergyRestart <- again
			}()
			if !ok || !again {
				return fmt.Errorf("Exit request received")
			}
		}
	}
}

func runRemote(host string, restart chan bool, wg *sync.WaitGroup) {
	wg.Add(1)
	parsed := sshHostConf(host)
	go func() {
		defer wg.Done()
		for {
			log.Printf("runRemoteLoop(%s)", host)
			err := runRemoteLoop(host, parsed, restart)
			if err != nil {
				log.Println("Error returned from runRemoteLoop:", err)
				return
			}
			time.Sleep(time.Second)
		}
	}()
}

func atMostEvery(every time.Duration, f func()) func() {
	var nextAvailable time.Time
	return func() {
		if time.Now().Before(nextAvailable) {
			return
		}
		nextAvailable = time.Now().Add(every)
		f()
	}
}

func delayed(delay time.Duration, f func()) func() {
	return func() {
		time.Sleep(delay)
		f()
	}
}

func xRandRchange() chan bool {
	events := make(chan event, 100)
	filtered := make(chan bool, 100)
	xrandrSubscribe(events)
	delay := 2 * time.Second
	debounce := time.Second
	runner := delayed(delay, atMostEvery(debounce, func() { filtered <- true }))
	go func() {
		for _ = range events {
			runner()
		}
	}()
	return filtered
}

const ctrlL = byte('L' - '@')

func terminalCtrlL() chan bool {
	gotCtrlL := make(chan bool, 100)
	if termstate.IsSupported() {
		go func() {
			defer termstate.DeferredReset(
				termstate.State.Cbreak,
				termstate.State.EchoOff,
			)()
			for {
				key := []byte{0}
				read, err := syscall.Read(0, key)
				if read == 0 || err != nil {
					return
				}
				if key[0] == ctrlL {
					gotCtrlL <- true
				}
			}
		}()
	}
	return gotCtrlL
}

func init() {
	var err error
	self, err = os.Hostname()
	check(err)
}

// A restartMux takes some number of incoming "you should restart" signals and
// fans them out to a list of listeners.
type restartMux struct {
	outs  map[string]chan bool
	mutex *sync.Mutex
}

func newRestartMux() *restartMux {
	return &restartMux{
		outs:  map[string]chan bool{},
		mutex: &sync.Mutex{},
	}
}

func (r *restartMux) listenFor(label string, in chan bool) {
	go func() {
		for {
			select {
			case val, ok := <-in:
				if !ok {
					log.Println("!ok " + label)
					return
				}
				r.notify(val)
			}
		}
	}()
}

func (r *restartMux) notify(val bool) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for _, out := range r.outs {
		go func(listener chan bool) {
			listener <- val
		}(out)
	}
}

func (r *restartMux) addOutput(name string) chan bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	out := make(chan bool, 100)
	r.outs[name] = out
	return out
}

func signalHandler() chan bool {
	restarter := make(chan bool, 1)
	gotSignal := make(chan os.Signal, 1)
	signal.Notify(gotSignal, syscall.SIGINT, syscall.SIGTERM, syscall.SIGPIPE)
	go func() {
		select {
		case s := <-gotSignal:
			log.Printf("Got signal: %d", s)
			restarter <- false
		}
	}()
	return restarter
}

func runMultilog(dir string, restarter chan bool, started chan bool) {
	logger := exec.Command("multilog", "t", "e", dir)
	loggerIn, err := logger.StdinPipe()
	check(err)
	log.SetOutput(loggerIn)
	log.SetFlags(0) // no timestamp
	loggerOut, err := logger.StderrPipe()
	check(err)
	timeParser := exec.Command("tai64nlocal")
	timeParser.Stdin = loggerOut
	timestampedLog, err := timeParser.StdoutPipe()
	check(err)
	startWithPgid(timeParser)
	startWithPgid(logger)
	go io.Copy(os.Stdout, timestampedLog)
	started <- true
	for {
		select {
		case again := <-restarter:
			if again {
				continue
			}
			go timeParser.Process.Wait()
			go logger.Process.Wait()
			loggerIn.Close()
		}
	}
}

func main() {
	var debugConf bool
	var multilogdir string
	flag.BoolVar(&debugConf, "print", debugConf, "Just print the config")
	flag.StringVar(&multilogdir, "multilog", multilogdir, "Set up multilog")
	flag.Parse()
	hosts := parseHosts(flag.Args())
	if debugConf {
		os.Stdout.Write(genSynergyConf(hosts))
		return
	}
	restarter := newRestartMux()
	restarter.listenFor("signal", signalHandler())
	restarter.listenFor("XRandR", xRandRchange())
	restarter.listenFor("Ctrl+L", terminalCtrlL())
	go func(debug chan bool) {
		for {
			select {
			case v := <-debug:
				log.Printf("Got restart signal (val=%v)", v)
			}
		}
	}(restarter.addOutput("-debugging-"))
	if multilogdir != "" {
		started := make(chan bool, 1)
		go runMultilog(multilogdir, restarter.addOutput("logger"), started)
		<-started
	}
	var wg sync.WaitGroup
	runLocal(hosts, restarter, &wg)
	for _, host := range hosts {
		if host != self {
			runRemote(host, restarter.addOutput(host), &wg)
		}
	}
	wg.Wait()
}
