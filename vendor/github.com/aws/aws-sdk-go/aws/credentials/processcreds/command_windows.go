package processcreds

import (
	"os/exec"
	"strings"
	"syscall"
)

func configureCommandLine(cmd *exec.Cmd) {
	args := cmd.Args[2:]
	command := args[0]
	if len(args) > 1 {
		quoted := make([]string, len(args))
		for i, arg := range args {
			quoted[i] = syscall.EscapeArg(arg)
		}
		command = strings.Join(quoted, " ")
	}
	// cmd.exe parses its command string differently from ordinary Windows argv.
	// /s removes only the outer quotes, preserving quoted paths and arguments.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CmdLine: syscall.EscapeArg(cmd.Path) + ` /d /s /c "` + command + `"`,
	}
}
