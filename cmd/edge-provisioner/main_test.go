package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func configureAPI(t *testing.T, handler http.Handler) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	oldURL := apiBaseURL
	apiBaseURL = server.URL
	t.Cleanup(func() { apiBaseURL = oldURL })
	for key, value := range map[string]string{"TS_TAILNET": "example.com", "TS_CLIENT_ID": "id", "TS_CLIENT_SECRET": "secret"} {
		t.Setenv(key, value)
	}
}

func TestIssueKeyWritesPrivateFileWithoutPrintingKey(t *testing.T) {
	const secret = "tskey-secret-value"
	configureAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			_, _ = w.Write([]byte(`{"access_token":"token"}`))
			return
		}
		var request struct {
			Capabilities struct {
				Devices struct {
					Create struct {
						Reusable  bool     `json:"reusable"`
						Ephemeral bool     `json:"ephemeral"`
						Tags      []string `json:"tags"`
					} `json:"create"`
				} `json:"devices"`
			} `json:"capabilities"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if request.Capabilities.Devices.Create.Reusable || request.Capabilities.Devices.Create.Ephemeral || !reflect.DeepEqual(request.Capabilities.Devices.Create.Tags, []string{"tag:edge"}) {
			t.Errorf("unexpected key options: %+v", request.Capabilities.Devices.Create)
		}
		_, _ = w.Write([]byte(`{"key":"` + secret + `"}`))
	}))
	path := filepath.Join(t.TempDir(), "key")
	var output strings.Builder
	if err := issueKey(context.Background(), []string{"--out", path}, &output); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != secret+"\n" {
		t.Fatalf("unexpected key contents %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("key file mode = %o, want 600", info.Mode().Perm())
	}
	if strings.Contains(output.String(), secret) {
		t.Fatal("key was written to output")
	}
}

func TestIssueKeyExistingFileDoesNotCallAPI(t *testing.T) {
	called := false
	configureAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		http.Error(w, "unexpected API call", http.StatusInternalServerError)
	}))
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := issueKey(context.Background(), []string{"--out", path}, &strings.Builder{}); err == nil {
		t.Fatal("expected exclusive file creation to fail")
	}
	if called {
		t.Fatal("API called despite existing destination file")
	}
	data, _ := os.ReadFile(path)
	if string(data) != "keep" {
		t.Fatalf("existing file was changed: %q", data)
	}
}

func TestIssueKeyAPIErrorRemovesReservedFileAndSanitizesResponse(t *testing.T) {
	configureAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			http.Error(w, "secret response body", http.StatusServiceUnavailable)
			return
		}
		t.Errorf("unexpected key request after token failure: %s", r.URL.Path)
	}))
	path := filepath.Join(t.TempDir(), "key")
	err := issueKey(context.Background(), []string{"--out", path}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("expected sanitized HTTP status error, got %v", err)
	}
	if strings.Contains(err.Error(), "secret response body") {
		t.Fatal("API response body leaked in error")
	}
	if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
		t.Fatalf("reserved output file was not removed: %v", statErr)
	}
}

func TestJoinValidatesAndCallsTailscaleWithKeyFilePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	oldRunner := runTailscale
	t.Cleanup(func() { runTailscale = oldRunner })
	var got []string
	runTailscale = func(ctx context.Context, args ...string) error {
		if _, ok := ctx.Deadline(); !ok {
			t.Error("tailscale context has no timeout")
		}
		got = append([]string(nil), args...)
		return nil
	}
	args := []string{"--key-file", path, "--client", "acme", "--site", "nyc", "--device", "edge1", "--environment", "prod", "--hostname", "gateway", "--routes", "10.2.0.0/24,192.168.4.0/24"}
	if err := run(context.Background(), append([]string{"join"}, args...), &strings.Builder{}, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	want := []string{"up", "--auth-key=file:" + path, "--hostname=gateway--acme--nyc--edge1--prod", "--advertise-routes=10.2.0.0/24,192.168.4.0/24"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %#v, want %#v", got, want)
	}
	if err := validateKeyFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected missing key file to fail")
	}
}

func TestJoinReportsTimeoutWithoutSubprocessError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	oldRunner := runTailscale
	t.Cleanup(func() { runTailscale = oldRunner })
	runTailscale = func(context.Context, ...string) error {
		return context.DeadlineExceeded
	}
	args := []string{"--key-file", path, "--client", "acme", "--site", "nyc", "--device", "edge1", "--environment", "prod", "--hostname", "gateway", "--routes", "10.2.0.0/24"}
	err := run(context.Background(), append([]string{"join"}, args...), &strings.Builder{}, &strings.Builder{})
	if err == nil || err.Error() != "tailscale up timed out" {
		t.Fatalf("expected sanitized timeout error, got %v", err)
	}
}

func TestValidateIdentityRejectsNonCanonicalOrNonPrivateRoutes(t *testing.T) {
	base := identityFlags{client: "acme", site: "nyc", device: "edge1", environment: "prod", hostname: "gateway", routes: "10.0.0.0/24"}
	for _, route := range []string{"10.1.2.3/8", "8.8.8.0/24", "2001:db8::/32", "10.0.0.0/24,"} {
		base.routes = route
		if _, _, err := validateIdentity(base); err == nil {
			t.Errorf("route %q unexpectedly accepted", route)
		}
	}
	base.routes = "10.0.0.0/24,10.0.0.0/24"
	if _, _, err := validateIdentity(base); err == nil || !strings.Contains(err.Error(), "duplicate route") {
		t.Fatalf("expected duplicate route rejection, got %v", err)
	}
}

func TestRoutePrefixBoundaries(t *testing.T) {
	base := identityFlags{client: "acme", site: "nyc", device: "edge1", environment: "prod", hostname: "gateway"}
	for _, route := range []string{"10.0.0.0/23", "10.0.0.0/31"} {
		base.routes = route
		if _, _, err := validateIdentity(base); err == nil {
			t.Errorf("route %q should be rejected", route)
		}
	}
	for _, route := range []string{"10.0.0.0/24", "10.0.0.0/29", "192.168.1.0/30"} {
		base.routes = route
		if _, _, err := validateIdentity(base); err != nil {
			t.Errorf("route %q should be accepted: %v", route, err)
		}
	}
}

func TestHostnameComponentsAreUnambiguous(t *testing.T) {
	first := identityFlags{client: "b-c", site: "d", device: "e", environment: "f", hostname: "a", routes: "10.0.0.0/24"}
	second := identityFlags{client: "c", site: "d", device: "e", environment: "f", hostname: "a-b", routes: "10.0.0.0/24"}
	firstHost, _, err := validateIdentity(first)
	if err != nil {
		t.Fatal(err)
	}
	secondHost, _, err := validateIdentity(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstHost == secondHost {
		t.Fatalf("distinct identities collided as %q", firstHost)
	}
	first.hostname = "a--b"
	if _, _, err := validateIdentity(first); err == nil {
		t.Fatal("expected double hyphen in a label to be rejected")
	}
}

func TestRouteComparisonIgnoresOrder(t *testing.T) {
	a := []string{"10.1.0.0/24", "192.168.1.0/24"}
	b := []string{"192.168.1.0/24", "10.1.0.0/24"}
	if !sameStrings(a, b) {
		t.Fatal("route comparison should be order-independent")
	}
}

func TestVerifyReportsApprovalAndRejectsUnauthorized(t *testing.T) {
	device := map[string]any{
		"nodeId": "node-1", "hostname": "gateway--acme--nyc--edge1--prod", "name": "gateway.tailnet.ts.net",
		"tags": []string{"tag:edge"}, "advertisedRoutes": []string{"10.1.0.0/24", "192.168.1.0/24"},
		"enabledRoutes": []string{}, "authorized": true, "isEphemeral": false,
	}
	configureAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/oauth/token") {
			_, _ = w.Write([]byte(`{"access_token":"token"}`))
			return
		}
		if r.URL.Path == "/api/v2/tailnet/example.com/devices" {
			// The list endpoint intentionally omits route and authorization details.
			_ = json.NewEncoder(w).Encode(map[string]any{"devices": []any{map[string]any{
				"nodeId": "node-1", "hostname": device["hostname"],
			}}})
			return
		}
		if r.URL.Path != "/api/v2/device/node-1" || r.URL.Query().Get("fields") != "all" {
			t.Errorf("unexpected detail request: %s?%s", r.URL.Path, r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode(device)
	}))
	args := []string{"--client", "acme", "--site", "nyc", "--device", "edge1", "--environment", "prod", "--hostname", "gateway", "--routes", "10.1.0.0/24,192.168.1.0/24"}
	var output strings.Builder
	if err := verify(context.Background(), args, &output, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "route approval pending") || !strings.Contains(output.String(), "gateway.tailnet.ts.net") {
		t.Fatalf("unexpected output: %q", output.String())
	}
	device["authorized"] = false
	if err := verify(context.Background(), args, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("expected authorization failure, got %v", err)
	}
	device["authorized"] = true
	device["isEphemeral"] = true
	if err := verify(context.Background(), args, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "ephemeral") {
		t.Fatalf("expected ephemeral failure, got %v", err)
	}
	device["isEphemeral"] = false
	device["tags"] = []string{"tag:other"}
	if err := verify(context.Background(), args, &strings.Builder{}, &strings.Builder{}); err == nil || !strings.Contains(err.Error(), "tag:edge") {
		t.Fatalf("expected tag failure, got %v", err)
	}
	device["tags"] = []string{"tag:edge"}
	device["enabledRoutes"] = []string{"10.1.0.0/24"}
	output.Reset()
	if err := verify(context.Background(), args, &output, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "route approval pending") {
		t.Fatalf("partial route approval should remain pending, got %q", output.String())
	}
	device["enabledRoutes"] = []string{"192.168.1.0/24", "10.1.0.0/24", "10.9.0.0/24"}
	output.Reset()
	if err := verify(context.Background(), args, &output, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "routes approved") {
		t.Fatalf("expected approved route status, got %q", output.String())
	}
}

func TestVerifyRejectsMissingOrMismatchedFullDeviceAndAPIError(t *testing.T) {
	args := []string{"--client", "acme", "--site", "nyc", "--device", "edge1", "--environment", "prod", "--hostname", "gateway", "--routes", "10.1.0.0/24"}
	for _, tc := range []struct {
		name       string
		list       []map[string]any
		detailCode int
		detail     map[string]any
		wantError  string
	}{
		{name: "missing", wantError: "device not found"},
		{name: "duplicate", list: []map[string]any{{"nodeId": "a", "hostname": "gateway--acme--nyc--edge1--prod"}, {"nodeId": "b", "hostname": "gateway--acme--nyc--edge1--prod"}}, wantError: "multiple devices"},
		{name: "missing id", list: []map[string]any{{"hostname": "gateway--acme--nyc--edge1--prod"}}, wantError: "no ID"},
		{name: "detail mismatch", list: []map[string]any{{"nodeId": "node-1", "hostname": "gateway--acme--nyc--edge1--prod"}}, detail: map[string]any{"hostname": "other-host"}, wantError: "do not match"},
		{name: "advertised route mismatch", list: []map[string]any{{"nodeId": "node-1", "hostname": "gateway--acme--nyc--edge1--prod"}}, detail: map[string]any{"hostname": "gateway--acme--nyc--edge1--prod", "advertisedRoutes": []string{"10.2.0.0/24"}, "authorized": true, "tags": []string{"tag:edge"}}, wantError: "advertised routes"},
		{name: "detail API failure", list: []map[string]any{{"nodeId": "node-1", "hostname": "gateway--acme--nyc--edge1--prod"}}, detailCode: http.StatusInternalServerError, wantError: "HTTP 500"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configureAPI(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/oauth/token") {
					_, _ = w.Write([]byte(`{"access_token":"token"}`))
					return
				}
				if r.URL.Path == "/api/v2/tailnet/example.com/devices" {
					_ = json.NewEncoder(w).Encode(map[string]any{"devices": tc.list})
					return
				}
				if tc.detailCode != 0 {
					http.Error(w, "sensitive response body", tc.detailCode)
					return
				}
				_ = json.NewEncoder(w).Encode(tc.detail)
			}))
			err := verify(context.Background(), args, &strings.Builder{}, &strings.Builder{})
			if err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("verify error = %v, want containing %q", err, tc.wantError)
			}
			if strings.Contains(err.Error(), "sensitive response body") {
				t.Fatal("API body leaked in error")
			}
		})
	}
}

func TestVerifyRejectsKeyFileFlag(t *testing.T) {
	err := verify(context.Background(), []string{"--key-file", "private"}, &strings.Builder{}, &strings.Builder{})
	if err == nil || !strings.Contains(err.Error(), "key-file") {
		t.Fatalf("expected unknown key-file flag error, got %v", err)
	}
}

func TestValidateKeyFileRejectsSymlinkAndLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := validateKeyFile(link); err == nil {
		t.Fatal("expected symlink rejection")
	}
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := validateKeyFile(loose); err == nil {
		t.Fatal("expected loose permissions rejection")
	}
}
