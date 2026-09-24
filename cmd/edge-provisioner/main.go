package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/tiptopcoder/tailscale-edge-provisioner/internal/tailscale"
)

const commandTimeout = 30 * time.Second

var (
	apiBaseURL   = "https://api.tailscale.com"
	runTailscale = func(ctx context.Context, args ...string) error {
		cmd := exec.CommandContext(ctx, "tailscale", args...)
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		return cmd.Run()
	}
)

type identityFlags struct {
	client, site, device, environment, hostname, routes string
}

func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(parent context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("expected issue-key, join, or verify subcommand")
	}
	ctx, cancel := context.WithTimeout(parent, commandTimeout)
	defer cancel()

	switch args[0] {
	case "issue-key":
		return issueKey(ctx, args[1:], stderr)
	case "join":
		return join(ctx, args[1:], stderr)
	case "verify":
		return verify(ctx, args[1:], stdout, stderr)
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func issueKey(ctx context.Context, args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("issue-key", flag.ContinueOnError)
	flags.SetOutput(stderr)
	outPath := flags.String("out", "", "path to create for the auth key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *outPath == "" || flags.NArg() != 0 {
		return errors.New("issue-key requires --out path")
	}
	f, err := os.OpenFile(*outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("could not create key file")
	}
	keepFile := false
	defer func() {
		_ = f.Close()
		if !keepFile {
			_ = os.Remove(*outPath)
		}
	}()
	client, err := apiClient()
	if err != nil {
		return err
	}
	key, err := client.CreateKey(ctx, "tag:edge")
	if err != nil {
		return fmt.Errorf("could not create auth key: %w", err)
	}
	if _, err := io.WriteString(f, key+"\n"); err != nil {
		return errors.New("could not write key file")
	}
	if err := f.Close(); err != nil {
		return errors.New("could not finish writing key file")
	}
	keepFile = true
	return nil
}

func join(ctx context.Context, args []string, stderr io.Writer) error {
	_, identity, keyPath, err := parseIdentity("join", args, stderr)
	if err != nil {
		return err
	}
	host, routes, err := validateIdentity(identity)
	if err != nil {
		return err
	}
	if keyPath == "" {
		return errors.New("join requires --key-file path")
	}
	if err := validateKeyFile(keyPath); err != nil {
		return err
	}
	if err := runTailscale(ctx, "up", "--auth-key=file:"+keyPath, "--hostname="+host, "--advertise-routes="+strings.Join(routes, ",")); err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errors.New("tailscale up timed out")
		}
		if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return errors.New("tailscale up canceled")
		}
		return errors.New("tailscale up failed")
	}
	return nil
}

// parseIdentity parses shared flags and exposes --key-file only to join.
func parseIdentity(name string, args []string, stderr io.Writer) (*flag.FlagSet, identityFlags, string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var id identityFlags
	flags.StringVar(&id.client, "client", "", "client label")
	flags.StringVar(&id.site, "site", "", "site label")
	flags.StringVar(&id.device, "device", "", "device label")
	flags.StringVar(&id.environment, "environment", "", "environment label")
	flags.StringVar(&id.hostname, "hostname", "", "hostname prefix")
	flags.StringVar(&id.routes, "routes", "", "comma-separated private IPv4 CIDRs (/24 through /30)")
	keyPath := ""
	if name == "join" {
		flags.StringVar(&keyPath, "key-file", "", "path to private auth key file")
	}
	if err := flags.Parse(args); err != nil {
		return flags, id, keyPath, err
	}
	if flags.NArg() != 0 {
		return flags, id, keyPath, fmt.Errorf("%s does not accept positional arguments", name)
	}
	return flags, id, keyPath, nil
}

func validateIdentity(id identityFlags) (string, []string, error) {
	for key, value := range map[string]string{"client": id.client, "site": id.site, "device": id.device, "environment": id.environment, "hostname": id.hostname} {
		if !validLabel(value) {
			return "", nil, fmt.Errorf("invalid %s label", key)
		}
	}
	host := strings.Join([]string{id.hostname, id.client, id.site, id.device, id.environment}, "--")
	if !validHostname(host) {
		return "", nil, errors.New("derived hostname exceeds DNS label constraints")
	}
	if id.routes == "" {
		return "", nil, errors.New("at least one route is required")
	}
	var routes []string
	seenRoutes := make(map[string]struct{})
	for _, route := range strings.Split(id.routes, ",") {
		ip, network, err := net.ParseCIDR(route)
		if err != nil || ip.To4() == nil || network.String() != route || !validPrivateSubnet(network) {
			return "", nil, fmt.Errorf("invalid route %q: require a canonical private IPv4 subnet from /24 through /30", route)
		}
		if _, exists := seenRoutes[route]; exists {
			return "", nil, fmt.Errorf("duplicate route %q", route)
		}
		seenRoutes[route] = struct{}{}
		routes = append(routes, route)
	}
	return host, routes, nil
}

func validPrivateSubnet(network *net.IPNet) bool {
	prefix, bits := network.Mask.Size()
	return bits == 32 && prefix >= 24 && prefix <= 30 && privateIPv4(network)
}

func validHostname(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func validLabel(value string) bool {
	if len(value) == 0 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' || strings.Contains(value, "--") {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func privateIPv4(network *net.IPNet) bool {
	if network.IP.To4() == nil {
		return false
	}
	for _, block := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, allowed, _ := net.ParseCIDR(block)
		if allowed.Contains(network.IP) && allowed.Contains(lastIP(network)) {
			return true
		}
	}
	return false
}

func lastIP(network *net.IPNet) net.IP {
	last := append(net.IP(nil), network.IP.To4()...)
	for i := range last {
		last[i] |= ^network.Mask[i]
	}
	return last
}

func validateKeyFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("could not access key file")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("key file must be a regular, private file (mode 0600 or stricter), not a symlink")
	}
	return nil
}

func verify(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	_, id, _, err := parseIdentity("verify", args, stderr)
	if err != nil {
		return err
	}
	host, routes, err := validateIdentity(id)
	if err != nil {
		return err
	}
	client, err := apiClient()
	if err != nil {
		return err
	}
	devices, err := client.ListDevices(ctx)
	if err != nil {
		return fmt.Errorf("could not list tailnet devices: %w", err)
	}
	var matches []tailscale.Device
	for _, device := range devices {
		if device.Hostname == host {
			matches = append(matches, device)
		}
	}
	if len(matches) == 0 {
		return errors.New("device not found")
	}
	if len(matches) != 1 {
		return errors.New("multiple devices match derived hostname")
	}
	if matches[0].ID == "" {
		return errors.New("matched device has no ID")
	}
	device, err := client.GetDevice(ctx, matches[0].ID)
	if err != nil {
		return fmt.Errorf("could not retrieve full device details: %w", err)
	}
	if device.Hostname != host {
		return errors.New("full device details do not match derived hostname")
	}
	if !device.Authorized {
		return errors.New("device is not authorized")
	}
	if device.IsEphemeral {
		return errors.New("device is ephemeral")
	}
	if !hasTag(device.Tags, "tag:edge") {
		return errors.New("device is missing required tag:edge")
	}
	if !sameStrings(device.AdvertisedRoutes, routes) {
		return errors.New("advertised routes do not match requested routes")
	}
	approved := containsAll(device.EnabledRoutes, routes)
	status := "route approval pending"
	if approved {
		status = "routes approved"
	}
	name := device.Name
	if name == "" {
		name = device.Hostname
	}
	fmt.Fprintf(stdout, "device %s (%s): %s\n", device.Hostname, name, status)
	return nil
}

func hasTag(tags []string, wanted string) bool {
	for _, tag := range tags {
		if tag == wanted {
			return true
		}
	}
	return false
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, value := range a {
		seen[value]++
	}
	for _, value := range b {
		seen[value]--
	}
	for _, count := range seen {
		if count != 0 {
			return false
		}
	}
	return true
}

func containsAll(values, required []string) bool {
	available := make(map[string]struct{}, len(values))
	for _, value := range values {
		available[value] = struct{}{}
	}
	for _, value := range required {
		if _, exists := available[value]; !exists {
			return false
		}
	}
	return true
}

func apiClient() (*tailscale.Client, error) {
	tailnet, clientID, secret := os.Getenv("TS_TAILNET"), os.Getenv("TS_CLIENT_ID"), os.Getenv("TS_CLIENT_SECRET")
	if tailnet == "" || clientID == "" || secret == "" {
		return nil, errors.New("TS_TAILNET, TS_CLIENT_ID, and TS_CLIENT_SECRET are required")
	}
	return tailscale.NewClient(apiBaseURL, tailnet, clientID, secret, &http.Client{Timeout: commandTimeout}), nil
}
