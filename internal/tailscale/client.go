package tailscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	maxResponseBody           = 1 << 20
	maxDeviceListResponseBody = 8 << 20
)

// Client is a small client for the Tailscale v2 API.
type Client struct {
	baseURL      string
	tailnet      string
	clientID     string
	clientSecret string
	httpClient   *http.Client
}

// Device describes the fields used by the provisioner from a Tailscale device.
type Device struct {
	ID               string   `json:"nodeId"`
	Hostname         string   `json:"hostname"`
	Name             string   `json:"name"`
	Tags             []string `json:"tags"`
	AdvertisedRoutes []string `json:"advertisedRoutes"`
	EnabledRoutes    []string `json:"enabledRoutes"`
	Authorized       bool     `json:"authorized"`
	IsEphemeral      bool     `json:"isEphemeral"`
}

// UnmarshalJSON accepts both nodeId and id for the device identifier.
func (d *Device) UnmarshalJSON(data []byte) error {
	var decoded struct {
		NodeID           string   `json:"nodeId"`
		ID               string   `json:"id"`
		Hostname         string   `json:"hostname"`
		Name             string   `json:"name"`
		Tags             []string `json:"tags"`
		AdvertisedRoutes []string `json:"advertisedRoutes"`
		EnabledRoutes    []string `json:"enabledRoutes"`
		Authorized       bool     `json:"authorized"`
		IsEphemeral      bool     `json:"isEphemeral"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*d = Device{
		ID: decoded.ID, Hostname: decoded.Hostname, Name: decoded.Name,
		Tags: decoded.Tags, AdvertisedRoutes: decoded.AdvertisedRoutes,
		EnabledRoutes: decoded.EnabledRoutes, Authorized: decoded.Authorized,
		IsEphemeral: decoded.IsEphemeral,
	}
	if decoded.NodeID != "" {
		d.ID = decoded.NodeID
	}
	return nil
}

// NewClient creates a client for the Tailscale API. A nil httpClient uses
// http.DefaultClient; callers are responsible for configuring timeouts.
func NewClient(baseURL, tailnet, clientID, clientSecret string, httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{
		baseURL:      strings.TrimRight(baseURL, "/"),
		tailnet:      tailnet,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   httpClient,
	}
}

// CreateKey creates a one-use auth key tagged with tag.
func (c *Client) CreateKey(ctx context.Context, tag string) (string, error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return "", err
	}
	body := struct {
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
	}{KeyType: "auth", ExpirySeconds: 3600}
	body.Capabilities.Devices.Create.Preauthorized = true
	body.Capabilities.Devices.Create.Tags = []string{tag}
	encoded, err := json.Marshal(body)
	if err != nil { // The fixed request structure cannot ordinarily fail to marshal.
		return "", errors.New("tailscale: could not encode key request")
	}
	path := "/api/v2/tailnet/" + url.PathEscape(c.tailnet) + "/keys"
	response, err := c.do(ctx, http.MethodPost, path, "", token, encoded, maxResponseBody)
	if err != nil {
		return "", err
	}
	var result struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(response, &result); err != nil || result.Key == "" {
		return "", errors.New("tailscale: invalid create-key response")
	}
	return result.Key, nil
}

// ListDevices returns devices in the configured tailnet.
func (c *Client) ListDevices(ctx context.Context) ([]Device, error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	path := "/api/v2/tailnet/" + url.PathEscape(c.tailnet) + "/devices"
	response, err := c.do(ctx, http.MethodGet, path, "", token, nil, maxDeviceListResponseBody)
	if err != nil {
		return nil, err
	}
	var result struct {
		Devices []Device `json:"devices"`
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, errors.New("tailscale: invalid device-list response")
	}
	return result.Devices, nil
}

// GetDevice returns the device identified by id, requesting all API fields.
func (c *Client) GetDevice(ctx context.Context, id string) (Device, error) {
	token, err := c.accessToken(ctx)
	if err != nil {
		return Device{}, err
	}
	path := "/api/v2/device/" + url.PathEscape(id)
	response, err := c.do(ctx, http.MethodGet, path, "fields=all", token, nil, maxResponseBody)
	if err != nil {
		return Device{}, err
	}
	var device Device
	if err := json.Unmarshal(response, &device); err != nil {
		return Device{}, errors.New("tailscale: invalid device response")
	}
	return device, nil
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	form := url.Values{
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
		"grant_type":    {"client_credentials"},
		"scope":         {"auth_keys devices:core:read"},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v2/oauth/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("tailscale: could not create token request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return "", sanitizedRequestError("token request", ctx, err)
	}
	data, err := readResponse(response, maxResponseBody)
	if err != nil {
		return "", err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("tailscale: token request failed (HTTP %d)", response.StatusCode)
	}
	var result struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &result); err != nil || result.AccessToken == "" {
		return "", errors.New("tailscale: invalid token response")
	}
	return result.AccessToken, nil
}

func (c *Client) do(ctx context.Context, method, path, query, token string, body []byte, responseLimit int64) ([]byte, error) {
	requestURL := c.baseURL + path
	if query != "" {
		requestURL += "?" + query
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL, bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("tailscale: could not create API request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, sanitizedRequestError("API request", ctx, err)
	}
	data, err := readResponse(response, responseLimit)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("tailscale: API request failed (HTTP %d)", response.StatusCode)
	}
	return data, nil
}

func readResponse(response *http.Response, limit int64) ([]byte, error) {
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, errors.New("tailscale: could not read response")
	}
	if int64(len(data)) > limit {
		return nil, errors.New("tailscale: response exceeds size limit")
	}
	return data, nil
}

func sanitizedRequestError(operation string, ctx context.Context, err error) error {
	if ctx.Err() != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("tailscale: %s timed out", operation)
		}
		return fmt.Errorf("tailscale: %s canceled", operation)
	}
	return fmt.Errorf("tailscale: %s failed", operation)
}
