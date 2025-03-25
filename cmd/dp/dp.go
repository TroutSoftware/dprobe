package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

var (
	PrivateKey string
	Remote     string
	KnownHosts string
	Insecure   bool
)

const usage = `
Usage:
  dprobe -pk PRIVATEKEY -c SERVER:PORT [-h KNOWN_HOSTS] [COMMAND]

Options:
  -pk, --private-key   SSH private key to use as client
  -c,  --connect       Remote host to connect to
  -h,  --known-hosts   SSH known_hosts file (to check server key)
  --insecure           Ignore remote host public key check
`

// connect, exec ls
func main() {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }
	flag.StringVar(&PrivateKey, "pk", "", "private key")
	flag.StringVar(&PrivateKey, "private-key", "", "private key")
	flag.StringVar(&Remote, "c", "", "remote addr:port")
	flag.StringVar(&Remote, "connect", "", "remote addr:port")
	flag.StringVar(&KnownHosts, "h", "", "known host")
	flag.StringVar(&KnownHosts, "known-hosts", "", "known host")
	flag.BoolVar(&Insecure, "insecure", false, "ignore remote")
	flag.Parse()

	if flag.NArg() <= 1 {
		flag.Usage()
		os.Exit(1)
	}
	command := strings.Join(flag.Args(), " ")

	if KnownHosts == "" {
		hd, _ := os.UserHomeDir()
		KnownHosts = filepath.Join(hd, ".ssh", "known_hosts")
	}

	keymat, err := os.ReadFile(PrivateKey)
	if err != nil {
		log.Fatalf("not a private key %s: %s", PrivateKey, err)
	}

	hk, err := ssh.ParsePrivateKey(keymat)
	if err != nil {
		log.Fatal("invalid key", err)
	}

	config := &ssh.ClientConfig{
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(hk),
		},
		HostKeyCallback: checkknownhost(KnownHosts),
	}
	if Insecure {
		config.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	client, err := ssh.Dial("tcp", Remote, config)
	if err != nil {
		log.Fatal(err)
	}

	socket := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "dprobe_agent_mx")
	if _, err := os.Stat(socket); err == nil {
		os.Remove(socket)
	}

	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}

	session.Stdout = os.Stdout
	session.Stderr = os.Stderr

	if err := session.Run(command); err != nil {
		log.Fatal(err)
	}
	session.Close()
	client.Close()
}

func checkknownhost(hostfile string) func(hostname string, remote net.Addr, key ssh.PublicKey) error {
	hosts, err := os.ReadFile(hostfile)
	if err != nil {
		return func(hostname string, remote net.Addr, key ssh.PublicKey) error { return err }
	}

	checkhost := make(map[string]ssh.PublicKey)

	for len(hosts) > 0 {
		_, h, pk, _, rest, err := ssh.ParseKnownHosts(hosts)
		if err != nil {
			log.Println("invalid host file", err)
		}

		for _, h := range h {
			checkhost[h] = pk
		}

		hosts = rest
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		hn, _, err := net.SplitHostPort(hostname)
		if err != nil {
			return fmt.Errorf("invalid hostname %s", hostname)
		}
		hostname = hn
		ours, ok := checkhost[hostname]
		if !ok {
			return fmt.Errorf("unknown host %s", hostname)
		}

		if ssh.FingerprintSHA256(ours) != ssh.FingerprintSHA256(key) {
			return fmt.Errorf("invalid host key %s", ssh.FingerprintSHA256(key))
		}

		return nil
	}
}
