package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestLiveConfiguration(t *testing.T) {
	valid := map[string]string{
		"S5CMD_TEST_MODE": "live", "S5CMD_TEST_ENDPOINT_URL": "https://storage.example.invalid",
		"S5CMD_REGION": "test-region", "S5CMD_IS_VIRTUAL_HOST": "true", "AWS_PROFILE": "acceptance",
		"S5CMD_I_KNOW_WHAT_IM_DOING": "1",
	}
	for _, name := range []string{"valid", "missing endpoint", "missing region", "missing profile", "missing consent", "invalid addressing", "plain HTTP", "URL credentials", "URL query", "static fallback", "alternate static fallback", "unknown mode"} {
		t.Run(name, func(t *testing.T) {
			env := make(map[string]string)
			for key, value := range valid {
				env[key] = value
			}
			switch name {
			case "missing endpoint":
				delete(env, s5cmdTestEndpointEnv)
			case "missing region":
				delete(env, s5cmdTestRegionEnv)
			case "missing profile":
				delete(env, "AWS_PROFILE")
			case "missing consent":
				delete(env, s5cmdTestIKnowWhatImDoingEnv)
			case "invalid addressing":
				env[s5cmdTestIsVirtualHost] = "false"
			case "plain HTTP":
				env[s5cmdTestEndpointEnv] = "http://storage.example.invalid"
			case "URL credentials":
				env[s5cmdTestEndpointEnv] = "https://user:synthetic-private-value@storage.example.invalid"
			case "URL query":
				env[s5cmdTestEndpointEnv] += "?token=synthetic-private-value"
			case "static fallback":
				env["AWS_ACCESS_KEY_ID"] = "synthetic-private-value"
			case "alternate static fallback":
				env["AWS_ACCESS_KEY"] = "synthetic-private-value"
				env["AWS_SECRET_KEY"] = "synthetic-private-value"
			case "unknown mode":
				env["S5CMD_TEST_MODE"] = "typo"
			}
			cfg, err := readLiveConfig(func(key string) string { return env[key] })
			if name == "valid" {
				if err != nil || cfg == nil {
					t.Fatal("valid live configuration rejected")
				}
				return
			}
			if err == nil {
				t.Fatal("invalid live configuration accepted")
			}
			if strings.Contains(err.Error(), "synthetic-private-value") {
				t.Fatal("configuration error disclosed a value")
			}
		})
	}
	cfg, err := readLiveConfig(func(string) string { return "" })
	if err != nil || cfg != nil {
		t.Fatal("default fake mode changed")
	}
}

func TestLiveStartupRejectsIncompleteRuns(t *testing.T) {
	env := make([]string, 0, len(os.Environ()))
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "AWS_") && !strings.HasPrefix(value, "S5CMD_") {
			env = append(env, value)
		}
	}
	for _, name := range []string{"missing config", "empty test selection", "skipped suite", "zero repetitions", "list tests"} {
		t.Run(name, func(t *testing.T) {
			args := []string{"-test.run=^TestDoesNotExist$"}
			switch name {
			case "skipped suite":
				args = []string{"-test.run=^TestAcceptanceStorage$", "-test.skip=TestAcceptanceStorage"}
			case "zero repetitions":
				args = []string{"-test.run=^TestAcceptanceStorage$", "-test.count=0"}
			case "list tests":
				args = []string{"-test.run=^TestAcceptanceStorage$", "-test.list=."}
			}
			cmd := exec.Command(os.Args[0], args...)
			cmd.Env = append(append([]string{}, env...), "S5CMD_TEST_MODE=live")
			if name != "missing config" {
				cmd.Env = append(cmd.Env, "S5CMD_TEST_ENDPOINT_URL=https://storage.example.invalid", "S5CMD_REGION=test-region", "S5CMD_IS_VIRTUAL_HOST=true", "S5CMD_I_KNOW_WHAT_IM_DOING=1", "AWS_PROFILE=acceptance")
			}
			output, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatal("incomplete live run succeeded")
			}
			if !strings.Contains(string(output), "live") {
				t.Fatal("live configuration diagnostic missing")
			}
		})
	}
}
