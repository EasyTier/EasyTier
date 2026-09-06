package host_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	corehost "github.com/EasyTier/EasyTier/easytier-go"
)

func TestWebClientEndToEnd(t *testing.T) {
	endpoint := os.Getenv("EASYTIER_WEB_E2E_ENDPOINT")
	apiURL := os.Getenv("EASYTIER_WEB_E2E_API")
	authToken := os.Getenv("EASYTIER_WEB_E2E_AUTH")
	if endpoint == "" || apiURL == "" || authToken == "" {
		t.Skip("EasyTier WebClient E2E environment is not configured")
	}
	userID, err := strconv.Atoi(os.Getenv("EASYTIER_WEB_E2E_USER_ID"))
	if err != nil || userID == 0 {
		userID = 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	host, err := corehost.New(ctx, corehost.Options{})
	if err != nil {
		t.Fatalf("create host: %v", err)
	}
	defer host.Close(ctx)
	application, err := host.CreateInstance(
		ctx,
		instanceConfig(t, 99, "10.154.0.1", 0, false, false),
	)
	if err != nil {
		t.Fatalf("create application instance: %v", err)
	}
	defer application.Close(ctx)

	const machineID = "11111111-2222-4333-8444-555555555555"
	client, err := host.ConnectWebClient(ctx, corehost.WebClientOptions{
		Endpoint:  endpoint,
		MachineID: machineID,
		Hostname:  "go-host-e2e",
	})
	if err != nil {
		t.Fatalf("connect WebClient: %v", err)
	}
	defer client.Close(ctx)
	waitFor(t, ctx, client.Connected, "WebClient connection")

	base := fmt.Sprintf(
		"%s/api/internal/users/%d/machines/%s/networks",
		strings.TrimRight(apiURL, "/"),
		userID,
		machineID,
	)
	waitFor(t, ctx, func() bool {
		body, status := webRequest(t, ctx, authToken, http.MethodGet, base, nil)
		var response struct {
			Running []json.RawMessage `json:"running_inst_ids"`
		}
		return status == http.StatusOK &&
			json.Unmarshal(body, &response) == nil &&
			len(response.Running) == 1
	}, "application instance heartbeat")

	const managedID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	networkName := "go-host-managed"
	networkSecret := "test"
	managedConfig := map[string]any{
		"instance_id":                    managedID,
		"dhcp":                           true,
		"network_name":                   networkName,
		"network_secret":                 networkSecret,
		"networking_method":              2,
		"listener_urls":                  []string{"tcp://0.0.0.0:11010", "udp://0.0.0.0:11010", "wg://0.0.0.0:11011"},
		"proxy_cidrs":                    []string{"10.200.0.0/24"},
		"disable_p2p":                    true,
		"disable_ipv6":                   true,
		"enable_vpn_portal":              true,
		"vpn_portal_listen_port":         11012,
		"vpn_portal_client_network_addr": "10.210.0.0",
		"vpn_portal_client_network_len":  24,
		"data_compress_algo":             2,
		"credential_file":                "/unsupported",
		"enable_quic_proxy":              true,
		"mapped_listeners":               []string{"wg://0.0.0.0:11012"},
		"advanced_settings":              true,
	}
	payload, err := json.Marshal(map[string]any{
		"config": managedConfig,
		"save":   false,
	})
	if err != nil {
		t.Fatalf("encode managed network request: %v", err)
	}
	body, status := webRequest(t, ctx, authToken, http.MethodPost, base, payload)
	if status != http.StatusOK {
		t.Fatalf("run managed instance: status=%d body=%s", status, body)
	}
	var managedInstance *corehost.Instance
	waitFor(t, ctx, func() bool {
		for _, instance := range host.Instances() {
			if instance.ID() == managedID {
				managedInstance = instance
				return true
			}
		}
		return false
	}, "managed instance creation")

	infoURL := base + "/info"
	body, status = webRequest(
		t,
		ctx,
		authToken,
		http.MethodGet,
		infoURL,
		[]byte(fmt.Sprintf(`{"inst_ids":["%s"]}`, managedID)),
	)
	if status != http.StatusOK ||
		!bytes.Contains(body, []byte(managedID)) ||
		!bytes.Contains(body, []byte(`"running":true`)) ||
		!bytes.Contains(body, []byte("tcp://")) ||
		!bytes.Contains(body, []byte("udp://")) ||
		bytes.Contains(body, []byte("wg://")) {
		t.Fatalf("collect managed status: status=%d body=%s", status, body)
	}

	portProbe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port-forward address: %v", err)
	}
	portForwardAddress := portProbe.Addr().String()
	portForwardPort := portProbe.Addr().(*net.TCPAddr).Port
	if err := portProbe.Close(); err != nil {
		t.Fatalf("release port-forward address: %v", err)
	}
	managedConfig["proxy_cidrs"] = []string{"10.201.0.0/24"}
	managedConfig["disable_relay_data"] = true
	managedConfig["port_forwards"] = []map[string]any{{
		"proto":     "tcp",
		"bind_ip":   "127.0.0.1",
		"bind_port": portForwardPort,
		"dst_ip":    "10.201.0.1",
		"dst_port":  80,
	}}
	payload, err = json.Marshal(map[string]any{
		"managed_network_configs": []map[string]any{{
			"instance_id":    managedID,
			"network_config": managedConfig,
		}},
		"config_revision": "revision-1",
	})
	if err != nil {
		t.Fatalf("encode managed network update: %v", err)
	}
	body, status = webRequest(t, ctx, authToken, http.MethodPut, base, payload)
	if status != http.StatusOK {
		t.Fatalf("update managed instance: status=%d body=%s", status, body)
	}
	waitFor(t, ctx, func() bool {
		connection, err := net.DialTimeout(
			"tcp",
			portForwardAddress,
			100*time.Millisecond,
		)
		if err != nil {
			return false
		}
		connection.Close()
		return true
	}, "managed instance hot patch")
	for _, instance := range host.Instances() {
		if instance.ID() == managedID && instance != managedInstance {
			t.Fatal("managed hot patch replaced the running instance")
		}
	}

	body, status = webRequest(
		t,
		ctx,
		authToken,
		http.MethodDelete,
		base+"/"+managedID,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("delete managed instance: status=%d body=%s", status, body)
	}
	waitFor(t, ctx, func() bool {
		instances := host.Instances()
		return len(instances) == 1 && instances[0].ID() == application.ID()
	}, "managed instance deletion")
}

func webRequest(
	t *testing.T,
	ctx context.Context,
	authToken string,
	method string,
	url string,
	body []byte,
) ([]byte, int) {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create %s request: %v", method, err)
	}
	request.Header.Set("X-Internal-Auth", authToken)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, 0
	}
	defer response.Body.Close()
	encoded, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read %s response: %v", method, err)
	}
	return encoded, response.StatusCode
}

func waitFor(
	t *testing.T,
	ctx context.Context,
	condition func() bool,
	description string,
) {
	t.Helper()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		if condition() {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("wait for %s: %v", description, ctx.Err())
		}
	}
}
