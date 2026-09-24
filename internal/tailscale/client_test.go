package tailscale

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestCreateKey(t *testing.T) {
	var tokenCalls, keyCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/oauth/token":
			tokenCalls++
			if r.Method != http.MethodPost || r.UserAgent() == "" {
				t.Errorf("unexpected token request: %s %s", r.Method, r.URL.Path)
			}
			values, _ := url.ParseQuery(readBody(t, r))
			if values.Get("client_id") != "client-id" || values.Get("client_secret") != "client-secret" || values.Get("grant_type") != "client_credentials" || values.Get("scope") != "auth_keys devices:core:read" {
				t.Errorf("unexpected token form: %v", values)
			}
			io.WriteString(w, `{"access_token":"bearer-secret"}`)
		case "/api/v2/tailnet/example.com/keys":
			keyCalls++
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer bearer-secret" {
				t.Errorf("unexpected key request: %s %s", r.Method, r.URL.Path)
			}
			var request struct {
				KeyType       string `json:"keyType"`
				ExpirySeconds int    `json:"expirySeconds"`
				Capabilities  struct {
					Devices struct {
						Create struct {
							Reusable      bool     `json:"reusable"`
							Ephemeral     bool     `json:"ephemeral"`
							Preauthorized bool     `json:"preauthorized"`
							Tags          []string `json:"tags"`
						} `json:"create"`
					} `json:"devices"`
				} `json:"capabilities"`
			}
			if err := json.Unmarshal([]byte(readBody(t, r)), &request); err != nil {
				t.Fatal(err)
			}
			create := request.Capabilities.Devices.Create
			if request.KeyType != "auth" || request.ExpirySeconds != 3600 || create.Reusable || create.Ephemeral || !create.Preauthorized || len(create.Tags) != 1 || create.Tags[0] != "tag:edge" {
				t.Errorf("unexpected key payload: %+v", request)
			}
			io.WriteString(w, `{"key":"tskey-secret"}`)
		default:
			t.Errorf("unexpected request path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, "example.com", "client-id", "client-secret", server.Client())
	key, err := client.CreateKey(context.Background(), "tag:edge")
	if err != nil {
		t.Fatal(err)
	}
	if key != "tskey-secret" || tokenCalls != 1 || keyCalls != 1 {
		t.Fatalf("key=%q token calls=%d key calls=%d", key, tokenCalls, keyCalls)
	}
}

func TestListDevicesAndGetDevice(t *testing.T) {
	var getQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			io.WriteString(w, `{"access_token":"token"}`)
			return
		}
		if r.URL.Path == "/api/v2/tailnet/tailnet.example/devices" {
			io.WriteString(w, `{"devices":[{"nodeId":"node-1","hostname":"edge","name":"edge.example","tags":["tag:edge"],"authorized":true,"isEphemeral":false}]}`)
			return
		}
		if r.URL.Path == "/api/v2/device/device-1" {
			getQuery = r.URL.RawQuery
			io.WriteString(w, `{"id":"device-1","hostname":"node","advertisedRoutes":["10.0.0.0/24"],"enabledRoutes":["10.0.0.0/24"],"authorized":true}`)
			return
		}
		t.Errorf("unexpected path %q", r.URL.Path)
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := NewClient(server.URL, "tailnet.example", "id", "secret", server.Client())
	devices, err := client.ListDevices(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 1 || devices[0].ID != "node-1" || devices[0].Hostname != "edge" || devices[0].Name != "edge.example" || !devices[0].Authorized || len(devices[0].Tags) != 1 || len(devices[0].AdvertisedRoutes) != 0 || len(devices[0].EnabledRoutes) != 0 || devices[0].IsEphemeral {
		t.Fatalf("unexpected device: %+v", devices)
	}
	device, err := client.GetDevice(context.Background(), "device-1")
	if err != nil {
		t.Fatal(err)
	}
	if getQuery != "fields=all" || device.ID != "device-1" || !device.Authorized || len(device.AdvertisedRoutes) != 1 || device.AdvertisedRoutes[0] != "10.0.0.0/24" || len(device.EnabledRoutes) != 1 || device.EnabledRoutes[0] != "10.0.0.0/24" {
		t.Fatalf("unexpected get result device=%+v query=%q", device, getQuery)
	}
}

func TestErrorsDoNotExposeSecretsOrResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			io.WriteString(w, `{"access_token":"token-secret"}`)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "response-secret https://private.example/?token=secret")
	}))
	defer server.Close()

	client := NewClient(server.URL, "tailnet", "client-id", "client-secret", server.Client())
	_, err := client.ListDevices(context.Background())
	if err == nil {
		t.Fatal("expected request error")
	}
	for _, secret := range []string{"response-secret", "private.example", "token-secret", "client-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error exposed %q: %v", secret, err)
		}
	}
}

func TestCreateKeyDoesNotRetryAndRejectsInvalidResponse(t *testing.T) {
	var keyCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			io.WriteString(w, `{"access_token":"token"}`)
			return
		}
		keyCalls++
		io.WriteString(w, "not-json")
	}))
	defer server.Close()
	client := NewClient(server.URL, "tailnet", "id", "secret", server.Client())
	if _, err := client.CreateKey(context.Background(), "tag:edge"); err == nil {
		t.Fatal("expected invalid response error")
	}
	if keyCalls != 1 {
		t.Fatalf("key creation calls = %d, want 1", keyCalls)
	}
}

func TestContextCancellationAndResponseLimit(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			io.WriteString(w, `{"access_token":"token"}`)
			return
		}
		close(started)
		<-r.Context().Done()
	}))
	defer server.Close()
	client := NewClient(server.URL, "tailnet", "id", "secret", server.Client())
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := client.ListDevices(ctx); done <- err }()
	<-started
	cancel()
	err := <-done
	if err == nil || !strings.Contains(err.Error(), "canceled") || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("unexpected cancellation error: %v", err)
	}

	oversized := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			io.WriteString(w, `{"access_token":"token"}`)
			return
		}
		io.WriteString(w, strings.Repeat("x", maxDeviceListResponseBody+1))
	}))
	defer oversized.Close()
	client = NewClient(oversized.URL, "tailnet", "id", "secret", oversized.Client())
	if _, err := client.ListDevices(context.Background()); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("expected response-limit error, got %v", err)
	}
}

func TestListDevicesAcceptsLargerResponse(t *testing.T) {
	const deviceCount = 8000
	devicesFixture := make([]Device, deviceCount)
	for i := range devicesFixture {
		name := fmt.Sprintf("edge-%05d.example", i)
		devicesFixture[i] = Device{
			ID: "node-" + fmt.Sprintf("%05d", i), Hostname: name, Name: name,
			Tags: []string{"tag:edge"}, AdvertisedRoutes: []string{}, EnabledRoutes: []string{},
			Authorized: true,
		}
	}
	listResponse, err := json.Marshal(struct {
		Devices []Device `json:"devices"`
	}{Devices: devicesFixture})
	if err != nil {
		t.Fatal(err)
	}
	if len(listResponse) <= maxResponseBody || int64(len(listResponse)) > maxDeviceListResponseBody {
		t.Fatalf("fixture size %d is outside expected range", len(listResponse))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v2/oauth/token" {
			io.WriteString(w, `{"access_token":"token"}`)
			return
		}
		w.Write(listResponse)
	}))
	defer server.Close()

	client := NewClient(server.URL, "tailnet", "id", "secret", server.Client())
	devices, err := client.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("ListDevices rejected a response larger than 1 MiB: %v", err)
	}
	if len(devices) != deviceCount {
		t.Fatalf("unexpected device count: got %d, want %d", len(devices), deviceCount)
	}
	if devices[0].Hostname != "edge-00000.example" || devices[len(devices)-1].Hostname != "edge-07999.example" {
		t.Fatalf("unexpected first/last hostnames: %q, %q", devices[0].Hostname, devices[len(devices)-1].Hostname)
	}
}

func TestTokenFailureAndDeadlineAreSanitized(t *testing.T) {
	t.Run("HTTP failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "client-secret access-token-secret", http.StatusUnauthorized)
		}))
		defer server.Close()
		client := NewClient(server.URL, "tailnet", "client-id", "client-secret", server.Client())
		_, err := client.ListDevices(context.Background())
		if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
			t.Fatalf("expected sanitized HTTP error, got %v", err)
		}
		for _, secret := range []string{"client-secret", "access-token-secret", server.URL} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error exposed %q: %v", secret, err)
			}
		}
	})

	t.Run("context deadline", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(100 * time.Millisecond)
			io.WriteString(w, `{"access_token":"late-token"}`)
		}))
		defer server.Close()
		client := NewClient(server.URL, "tailnet", "id", "secret", server.Client())
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		defer cancel()
		_, err := client.ListDevices(ctx)
		if err == nil || !strings.Contains(err.Error(), "timed out") || strings.Contains(err.Error(), server.URL) {
			t.Fatalf("expected sanitized deadline error, got %v", err)
		}
	})
}

func TestDeviceIDFallsBackToID(t *testing.T) {
	var d Device
	if err := json.Unmarshal([]byte(`{"id":"legacy-id","name":"n"}`), &d); err != nil {
		t.Fatal(err)
	}
	if d.ID != "legacy-id" {
		t.Fatalf("ID = %q", d.ID)
	}
}

func readBody(t *testing.T, r *http.Request) string {
	t.Helper()
	data, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
