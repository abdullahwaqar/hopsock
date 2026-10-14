package hopsock

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ExitInfo is what a preflight request learned about the exit node.
type ExitInfo struct {
	IP       string
	Location string // "City, Region, CC" when the endpoint reports it
	Org      string
	Raw      string // response body, trimmed
	Latency  time.Duration
}

// Preflight fetches testURL through d (DNS resolved remotely) and pulls
// out the exit IP if the response is JSON from a "what's my IP" service.
func Preflight(ctx context.Context, d Dialer, testURL string) (*ExitInfo, error) {
	tr := &http.Transport{
		DialContext:         d.DialContext,
		TLSHandshakeTimeout: 15 * time.Second,
		DisableKeepAlives:   true,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hopsock-preflight")
	req.Header.Set("Accept", "application/json, text/plain")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	info := &ExitInfo{Latency: time.Since(start), Raw: strings.TrimSpace(string(body))}
	if resp.StatusCode >= 400 {
		return info, fmt.Errorf("test URL returned %s", resp.Status)
	}
	parseExit(info, body)
	return info, nil
}

func parseExit(info *ExitInfo, body []byte) {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		// Plain text services (api.ipify.org, icanhazip.com) return just the IP.
		if s := strings.TrimSpace(string(body)); len(s) < 64 && !strings.ContainsAny(s, " \n<") {
			info.IP = s
		}
		return
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			// "a.b" looks one level into a nested object.
			parts := strings.SplitN(k, ".", 2)
			v, ok := m[parts[0]]
			if ok && len(parts) == 2 {
				if mm, isMap := v.(map[string]any); isMap {
					v, ok = mm[parts[1]]
				} else {
					ok = false
				}
			}
			if ok {
				if s, isStr := v.(string); isStr && s != "" {
					return s
				}
			}
		}
		return ""
	}
	info.IP = str("ip", "query", "proxy.ip", "origin")
	var loc []string
	for _, v := range []string{
		str("city", "city.name"),
		str("region", "regionName", "region_name", "city.state"),
		str("country", "country_code", "countryCode", "country.code"),
	} {
		if v != "" {
			loc = append(loc, v)
		}
	}
	info.Location = strings.Join(loc, ", ")
	info.Org = str("org", "isp", "asn.organization", "isp.isp", "isp.organization")
}
