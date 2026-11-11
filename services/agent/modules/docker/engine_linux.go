package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/pavlith/arc/sdk/security"
)

const engineSocket = "/var/run/docker.sock"
const apiVersion = "/v1.44"

var errMissing = errors.New("docker: object not found")

func localEngine(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (d *Driver) call(ctx context.Context, method, path string, input, output any) error {
	var body io.Reader
	if input != nil {
		raw, err := json.Marshal(input)
		if err != nil {
			return security.ErrUnavailable
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+apiVersion+path, body)
	if err != nil {
		return security.ErrUnavailable
	}
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return security.ErrUnavailable
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNotFound:
		return errMissing
	case http.StatusOK, http.StatusCreated, http.StatusNoContent, http.StatusNotModified:
		if output != nil {
			raw, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
			if err != nil || len(raw) > 1<<20 || json.Unmarshal(raw, output) != nil {
				return security.ErrUnavailable
			}
		}
		return nil
	default:
		return security.ErrUnavailable
	}
}
