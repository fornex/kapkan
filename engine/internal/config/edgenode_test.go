package config

import (
	"strings"
	"testing"
)

const edgeYAML = `
controller:
  url: https://brain.example.net:8443
  token_env: KAPKAN_EDGE_TOKEN
  name: edge-1
`

func TestParseEdgeNodeDefaults(t *testing.T) {
	e, err := ParseEdgeNode([]byte(edgeYAML))
	if err != nil {
		t.Fatal(err)
	}
	if !e.DryRunResolved() {
		t.Fatal("dry_run must default to true")
	}
	if e.StateDir != "/var/lib/kapkan/edge" || e.SocketsDir != "/run/kapkan" || e.Terminator.Binary != "nginx" || e.Terminator.Reload != EdgeReloadExec || e.Controller.ReportIntervalSeconds != 10 {
		t.Fatalf("defaults: %+v", e)
	}
	full := edgeYAML + `
dry_run: false
state_dir: /srv/kapkan/edge
sockets_dir: /run/kapkan-edge
socket_group: www-data
terminator:
  binary: angie
  main_conf: /etc/angie/angie.conf
  reload: command
  command: [systemctl, reload, angie]
acme:
  directory: https://acme-staging-v02.api.letsencrypt.org/directory
  fallback: https://acme.zerossl.com/v2/DV90
  contact: ["mailto:ops@example.com"]
status_listen: 127.0.0.1:9102
omit_catch_all: true
disable_ipv6: true
`
	e, err = ParseEdgeNode([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	if e.DryRunResolved() || e.Terminator.Binary != "angie" || len(e.Terminator.Command) != 3 || e.ACME.Contact[0] != "mailto:ops@example.com" || !e.OmitCatchAll {
		t.Fatalf("full: %+v", e)
	}
}

func TestParseEdgeNodeRejects(t *testing.T) {
	cases := []struct{ name, yaml, wantErr string }{
		{"unknown key", edgeYAML + "zones: []\n", "field zones not found"},
		{"no url", "controller:\n  token_env: T\n  name: e\n", "controller.url is required"},
		{"url with path", strings.Replace(edgeYAML, ":8443", ":8443/api", 1), "must not carry a path"},
		{"bad token env", strings.Replace(edgeYAML, "KAPKAN_EDGE_TOKEN", "9bad", 1), "token_env"},
		{"bad name", strings.Replace(edgeYAML, "edge-1", "edge 1", 1), "controller.name"},
		{"relative state dir", edgeYAML + "state_dir: state\n", "state_dir must be an absolute path"},
		{"sockets dir with space", edgeYAML + "sockets_dir: \"/run/kap kan\"\n", "sockets_dir must be an absolute path"},
		{"bad group", edgeYAML + "socket_group: \"www data\"\n", "socket_group"},
		{"relative main_conf", edgeYAML + "terminator:\n  main_conf: nginx.conf\n", "terminator.main_conf"},
		{"signal without pid", edgeYAML + "terminator:\n  reload: signal\n", "pid_file"},
		{"command without argv", edgeYAML + "terminator:\n  reload: command\n", "terminator.command"},
		{"unknown reload", edgeYAML + "terminator:\n  reload: magic\n", "not exec, signal or command"},
		{"bad acme url", edgeYAML + "acme:\n  directory: nope\n", "acme.directory"},
		{"fallback equals directory", edgeYAML + "acme:\n  directory: https://ca.example/d\n  fallback: https://ca.example/d\n", "different directory"},
		{"contact not mailto", edgeYAML + "acme:\n  contact: [ops@example.com]\n", "mailto:"},
		{"bad status listen", edgeYAML + "status_listen: nope\n", "status_listen"},
		{"zero report interval", strings.Replace(edgeYAML, "  name: edge-1\n", "  name: edge-1\n  report_interval_seconds: -1\n", 1), "report_interval_seconds"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseEdgeNode([]byte(c.yaml))
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("err = %v, want %q", err, c.wantErr)
			}
		})
	}
}
