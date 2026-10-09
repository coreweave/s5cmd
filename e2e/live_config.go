package e2e

import (
	"errors"
	"net/url"
	"strings"
)

type liveConfig struct{ endpoint, region, profile string }

// A partial live configuration must never select the local fake server.
func readLiveConfig(getenv func(string) string) (*liveConfig, error) {
	mode := getenv("S5CMD_TEST_MODE")
	if mode == "" || mode == "fake" {
		return nil, nil
	}
	if mode != "live" {
		return nil, errors.New("unsupported S5CMD_TEST_MODE")
	}
	for _, key := range []string{"S5CMD_TEST_ENDPOINT_URL", "S5CMD_REGION", "AWS_PROFILE"} {
		if strings.TrimSpace(getenv(key)) == "" {
			return nil, errors.New("missing required live configuration: " + key)
		}
	}
	if getenv("S5CMD_I_KNOW_WHAT_IM_DOING") != "1" {
		return nil, errors.New("live tests require explicit consent")
	}
	if getenv("S5CMD_IS_VIRTUAL_HOST") != "true" {
		return nil, errors.New("live tests require virtual-host addressing")
	}
	u, err := url.Parse(getenv("S5CMD_TEST_ENDPOINT_URL"))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("live endpoint must be an HTTPS origin without credentials")
	}
	for _, key := range []string{"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN", "S5CMD_ACCESS_KEY_ID", "S5CMD_SECRET_ACCESS_KEY"} {
		if getenv(key) != "" {
			return nil, errors.New("live tests require profile credentials without static environment credentials")
		}
	}
	if value := strings.ToLower(getenv("AWS_SDK_LOAD_CONFIG")); value != "" && value != "1" && value != "true" {
		return nil, errors.New("live tests require shared AWS configuration")
	}
	return &liveConfig{endpoint: u.String(), region: getenv("S5CMD_REGION"), profile: getenv("AWS_PROFILE")}, nil
}
