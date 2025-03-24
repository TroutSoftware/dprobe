package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

var (
	PrivateKey string
)

// connect, exec ls
func main() {
	flag.StringVar(&PrivateKey, "pk", "", "private key")
	flag.Parse()

	var j int
	for i := range flag.Args() {
		if flag.Arg(i) == "--" {
			j = i
		}
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
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", "localhost:2022", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Fatal("Failed to create session: ", err)
	}
	defer session.Close()

	// Once a Session is created, you can execute a single command on
	// the remote side using the Run method.
	var b bytes.Buffer
	session.Stdout = &b

	if err := session.Run(strings.Join(flag.Args()[j:], " ")); err == nil {
		err = fmt.Errorf("ssh: command %v failed", err)
	}
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(b.String())
}

type execMsg struct {
	Command string
	Args    []string
}
