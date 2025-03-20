package agent

import "os/exec"

type Ply struct {
	Program string `cmd:"program"`
}

func (p *Ply) Do() {
	exec.Command("ply", p.Program)
}
