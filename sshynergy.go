package main

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
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
	name string
	subsections []section
	config options
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
		lines = append(lines, indent + k + " = " + v + "\n")
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

func genSynergyConf(hosts []string) []byte {
	var conf string
	opts := section{
		name:   "options",
		config: options{"screenSaverSync": "false"},
	}
	screens := section{name: "screens", subsections: []section{}}
	for _, host := range hosts {
		screens.subsections = append(screens.subsections, section{name: host})
	}
	links := section{name: "links", subsections: []section{}}
	for i, host := range hosts {
		left, right := hosts[(len(hosts)+i-1) % len(hosts)],hosts[(i+1) % len(hosts)]
		links.subsections = append(links.subsections, section{
			name: host,
			config: options{"left": left, "right": right},
		})
	}
	for _, s := range []section{opts, screens, links} {
		conf += s.format()
	}
	return []byte(conf)
}

var self string

func parseHosts() []string {
	var ret []string
	addedSelf := false
	for _, arg := range os.Args[1:len(os.Args)] {
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

func serveSynergy(hosts []string, ready chan error, restart chan bool) {
	cmd := exec.Command("synergys", "-f", "-a", "127.0.0.1", "-c", "/dev/stdin")
	stdin, err := cmd.StdinPipe()
	check(err)
	stdin.Write(genSynergyConf(hosts))
	check(stdin.Close())
	check(cmd.Start())
	ready <- nil
	log.Println("Local synergys pid:", cmd.Process.Pid)
	finished := make(chan error, 1)
	go func() {
		finished <- cmd.Wait()
	}()
	select {
	case <-restart:
		cmd.Process.Kill()
	case e := <-finished:
		check(e)
	}
}

func getAgent() sshagent.Agent {
	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	check(err)
	return sshagent.NewClient(conn)
}

type opensshconf struct {
	user, hostname, port string
	idfiles []string
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
		User: conf.user,
		Auth: conf.agentAuth(),
	})
}

func sshHostConf(host string) opensshconf {
	var conf opensshconf
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
			file := val
			if file[0] == '~' {
				file = os.Getenv("HOME") + file[1:len(file)]
			}
			paths := strings.Split(file, "/")
			conf.idfiles = append(conf.idfiles, file)
			conf.idfiles = append(conf.idfiles, paths[len(paths)-1])
		}
	}
	return conf
}

func serveConnection(remote, local net.Conn) {
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
	wg.Wait()
	remote.Close()
	local.Close()
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

	go func(){
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

func forwardRemote(conn *ssh.Client) error {
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
		serveConnection(remote, local)
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
	err = sess.Start("synergyc -1 -f -n " + host + " localhost")
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
	case again := <-restart:
		sess.Close()
		if again {
			return nil
		}
		return io.EOF
	case e := <-finished:
		check(e)
		return nil
	}
}

func runLocal(hosts []string, restarter *restartMux) {
	ready := make(chan error, 1)
	go func() {
		for {
			serveSynergy(hosts, ready, restarter.addOutput(self))
		}
	}()
	check(<-ready)
}

func runRemoteLoop(host string, parsed opensshconf, restart chan bool) error {
	conn, err := parsed.dial()
	if isNetErr(err) {
		return err
	}
	check(err)
	defer conn.Close()

	restartForward := make(chan bool, 1)
	restartSynergy := make(chan bool, 1)
	bailed := make(chan bool, 1)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			log.Println("Forwarding remote port for", host)
			err := forwardRemote(conn, restartForward)
			if isNetErr(err) {
				log.Println("Net error forwarding:", err)
				log.Println("Bailing to restart", host)
				restartSynergy <- false
				return
			} else if err != nil {
				log.Println("Error forwarding remote:", err)
				time.Sleep(time.Second)
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			err := runSynergyOn(conn, host, restartSynergy)
			if err != nil {
				log.Println("Error running synergyc:", err)
				log.Println("Not restarting synergyc on", host)
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		bailed <- true
	}()

	for {
		select {
		case <-restart:
			restartForward <- true
			restartSynergy <- true
		case <-bailed:
			break
		}
	}

	return nil
}

func runRemote(host string, restart chan bool) {
	parsed := sshHostConf(host)
	go func() {
		for {
			err := runRemoteLoop(host, parsed, restart)
			if err != nil {
				log.Println("Error running remote:", err)
				time.Sleep(time.Second)
			}
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

func restartOnXRandR() chan bool {
	events := make(chan event, 100)
	filtered := make(chan bool, 100)
	xrandrSubscribe(events)
	delay := 2*time.Second
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
	outs map[string]chan bool
	mutex *sync.Mutex
}

func newRestartMux() *restartMux {
	return &restartMux{
		outs:  map[string]chan bool{},
		mutex: &sync.Mutex{},
	}
}

func (r *restartMux) listenFor(in chan bool) {
	go func() {
		select {
		case <-in:
			r.notify()
		}
	}()
}

func (r *restartMux) notify() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	for _, out := range r.outs {
		go func() {
			out <- true
		}()
	}
}

func (r *restartMux) addOutput(name string) chan bool {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	out := make(chan bool, 100)
	r.outs[name] = out
	return out
}

func main() {
	hosts := parseHosts()
	restarter := newRestartMux()
	restarter.listenFor(restartOnXRandR())
	restarter.listenFor(terminalCtrlL())
	runLocal(hosts, restarter)
	go func(restarter chan bool) {
		for _ = range restarter {
			log.Println("Restart requested")
		}
	}(restarter.addOutput("-debugging-"))
	for _, host := range hosts {
		if host != self {
			runRemote(host, restarter.addOutput(host))
		}
	}
	select {}
}
