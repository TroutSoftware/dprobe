package main

import (
	"log"
	"os"

	"github.com/TroutSoftware/dprobe/server"
)

func main() {
	wd, _ := os.Getwd()
	agent.InstallFolder = wd
	if err := agent.ListenSSH("localhost:2022"); err != nil {
		log.Fatal(err)
	}
}
