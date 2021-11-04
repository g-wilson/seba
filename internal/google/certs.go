package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"gopkg.in/square/go-jose.v2"
)

const CertsURL = "https://www.googleapis.com/oauth2/v3/certs"

var maxAgeHeaderRegexp = regexp.MustCompile("max-age=([0-9]*)")

type certs struct {
	Keys   *jose.JSONWebKeySet
	Expiry time.Time
}

var cache *certs

func (v *GoogleVerifier) getCertificates(ctx context.Context) (*jose.JSONWebKeySet, error) {
	if cache != nil {
		if time.Now().Before(cache.Expiry) {
			return cache.Keys, nil
		}
	}

	var client *http.Client

	if v.httpClient != nil {
		client = v.httpClient
	} else {
		client = &http.Client{
			Timeout: 3 * time.Second,
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, CertsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("createrequest: %w", err)
	}

	res, err := client.Do(req)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("request timed out: %w", err)
		}
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer res.Body.Close()

	cacheControl := res.Header.Get("cache-control")
	ttl := int64(7200) // 2 hours

	if len(cacheControl) > 0 {
		match := maxAgeHeaderRegexp.FindAllStringSubmatch(cacheControl, -1)

		if len(match) > 0 && len(match[0]) == 2 {
			maxAge := match[0][1]

			maxAgeInt, err := strconv.ParseInt(maxAge, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("cacheparser: %w", err)
			}

			ttl = maxAgeInt
		}
	}

	keys := jose.JSONWebKeySet{}
	err = json.NewDecoder(res.Body).Decode(&keys)
	if err != nil {
		return nil, fmt.Errorf("keydecoder: %w", err)
	}

	for _, k := range keys.Keys {
		if !k.Valid() {
			return nil, fmt.Errorf("keydecoder: invalid key: %s", k.KeyID)
		}
	}

	cache = &certs{
		Keys:   &keys,
		Expiry: time.Now().Add(time.Second * time.Duration(ttl)),
	}

	return cache.Keys, nil
}
