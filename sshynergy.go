package main

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"

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
	return ret
}

func runLocal(hosts []string) {
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

func agentAuth() []ssh.AuthMethod {
	return []ssh.AuthMethod{ssh.PublicKeysCallback(getAgent().Signers)}
}

type opensshconf struct {
	user, hostname, port string
}

func (conf opensshconf) address() string {
	port := conf.port
	if port == "" {
		port = "22"
	}
	return conf.hostname + ":" + port
}

func sshHostConf(host string) opensshconf {
	var conf opensshconf
	parsed, err := exec.Command("ssh", "-G", host).Output()
	check(err)
	scanner := bufio.NewScanner(bytes.NewReader(parsed))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), " ")
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
		}
	}
	return conf
}

func routeTraffic(src, dst net.Conn, done chan bool) {
	_, err := io.Copy(src, dst)
	check(err)
	done <- true
}

func serveConnection(remote, local net.Conn) {
	defer local.Close()
	done := make(chan bool)
	go routeTraffic(remote, local, done)
	go routeTraffic(local, remote, done)
	<-done
}

func forwardRemote(conn *ssh.Client) {
	listener, err := conn.Listen("tcp", "127.0.0.1:24800")
	check(err)
	defer listener.Close()

	for {
		remote, err := listener.Accept()
		check(err)
		defer remote.Close()

		local, err := net.Dial("tcp", "localhost:24800")
		check(err)
		defer local.Close()

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

func runRemote(host string) {
	parsed := sshHostConf(host)
	conn, err := ssh.Dial("tcp", parsed.address(), &ssh.ClientConfig{
		User: parsed.user,
		Auth: agentAuth(),
	})
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
