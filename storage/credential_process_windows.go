package storage

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func configureCredentialProcess(cmd *exec.Cmd) {
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
	cmd.Cancel = func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		kill := exec.CommandContext(ctx, "taskkill.exe", "/T", "/F", "/PID", strconv.Itoa(cmd.Process.Pid))
		if err := kill.Run(); err != nil {
			return cmd.Process.Kill()
		}
		return nil
	}
}
