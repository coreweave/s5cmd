//go:build !windows

package processcreds

import "os/exec"

func configureCommandLine(_ *exec.Cmd) {}
