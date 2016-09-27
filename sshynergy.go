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

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
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

func serveSynergy(hosts []string) {
	cmd := exec.Command("synergys", "-f", "-a", "127.0.0.1", "-c", "/dev/stdin")
	stdin, err := cmd.StdinPipe()
	check(err)
	stdin.Write(genSynergyConf(hosts))
	check(stdin.Close())
	check(cmd.Start())
	check(cmd.Wait())
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

func forwardRemote(conn *ssh.Client) {
	listener, err := conn.Listen("tcp", "127.0.0.1:24800")
	check(err)
	defer listener.Close()

	for {
		remote, err := listener.Accept()
		check(err)
		local, err := net.Dial("tcp", "localhost:24800")
		if err != nil {
			log.Println(err)
			continue
		}
		serveConnection(remote, local)
	}
}

func runSynergyOn(conn *ssh.Client, host string) {
	sess, err := conn.NewSession()
	check(err)
	defer sess.Close()
	sess.Start("synergyc -1 -f -n " + host + " localhost")
	sess.Wait()
}

func runLocal(hosts []string) {
	for {
		serveSynergy(hosts)
	}
}

func runRemote(host string) {
	parsed := sshHostConf(host)
	conn, err := parsed.dial()
	check(err)
	defer conn.Close()

	go func() {
		for {
			forwardRemote(conn)
		}
	}()
	go func() {
		for {
			runSynergyOn(conn, host)
		}
	}()
	select {}
}

func init() {
	var err error
	self, err = os.Hostname()
	check(err)
}

func main() {
	hosts := parseHosts()
	for _, host := range hosts {
		if host != self {
			go runRemote(host)
		} else {
			go runLocal(hosts)
		}
	}
	select {}
}
