package main

import (
	"strings"
	"testing"
)

func TestParseOptions(t *testing.T) {
	options, err := parseOptions([]string{
		"--web-endpoint", " tcp://config.example.com:22020/team ",
		"--web-machine-id", " 11111111-2222-4333-8444-555555555555 ",
		"--web-hostname", " edge-gateway ",
		"--web-secure",
	})
	if err != nil {
		t.Fatalf("parse options: %v", err)
	}
	if options.endpoint != "tcp://config.example.com:22020/team" ||
		options.machineID != "11111111-2222-4333-8444-555555555555" ||
		options.hostname != "edge-gateway" ||
		!options.secure {
		t.Fatalf("parsed options = %+v", options)
	}
}

func TestParseOptionsRequiresEndpointAndMachineID(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		want      string
	}{
		{
			name: "endpoint",
			arguments: []string{
				"--web-machine-id", "11111111-2222-4333-8444-555555555555",
			},
			want: "--web-endpoint",
		},
		{
			name:      "machine ID",
			arguments: []string{"--web-endpoint", "tcp://config.example.com:22020/team"},
			want:      "--web-machine-id",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseOptions(test.arguments)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parse error = %v, want containing %q", err, test.want)
			}
		})
	}
}
