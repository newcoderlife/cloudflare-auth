package cloudflare_auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap"
)

type JWKS struct {
	Keys []JSONWebKey `json:"keys"`
}

type JSONWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type CacheItem struct {
	Body      []byte
	CreatedAt int64
}

var cache sync.Map

func init() {
	caddy.RegisterModule(CloudflareAuth{})
	httpcaddyfile.RegisterHandlerDirective("cloudflare_auth", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("cloudflare_auth", httpcaddyfile.Before, "reverse_proxy")
}

type CloudflareAuth struct {
	Aud string `json:"aud,omitempty"`

	logger *zap.Logger
}

func (CloudflareAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cloudflare_auth",
		New: func() caddy.Module { return new(CloudflareAuth) },
	}
}

func (m *CloudflareAuth) Provision(ctx caddy.Context) error {
	if m.Aud == "" {
		return fmt.Errorf("audience (aud) must be set")
	}
	m.logger = ctx.Logger()
	return nil
}

func (m *CloudflareAuth) downloadPubKey(jwtToken string) *JWKS {
	token, _, err := jwt.NewParser().ParseUnverified(jwtToken, jwt.MapClaims{})
	if err != nil {
		m.logger.Sugar().Errorf("Failed to parse JWT token: %s, err: %v", jwtToken, err)
		return nil
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		m.logger.Sugar().Errorf("Failed to parse JWT claims: %s, err: %v", toString(claims), err)
		return nil
	}

	iss, ok := claims["iss"].(string)
	if !ok || len(iss) == 0 {
		m.logger.Sugar().Errorf("Failed to parse JWT iss, claims: %s, err: %v", toString(claims), err)
		return nil
	}

	var body []byte
	uri := fmt.Sprintf("%s/cdn-cgi/access/certs", iss)
	if cached, ok := cache.Load(uri); ok && time.Now().Unix()-cached.(CacheItem).CreatedAt < 600 {
		body = cached.(CacheItem).Body
	} else {
		resp, err := http.Get(uri)
		if err != nil || resp.StatusCode != http.StatusOK {
			m.logger.Sugar().Errorf("Failed to download public key, response: %s, err: %v", toString(resp), err)
			return nil
		}
		defer resp.Body.Close()

		if body, err = io.ReadAll(resp.Body); err != nil {
			m.logger.Sugar().Errorf("Failed to read response body: %s, err: %v", body, err)
			return nil
		}
		cache.Store(uri, CacheItem{Body: body, CreatedAt: time.Now().Unix()})
	}

	jwks := new(JWKS)
	if err = json.Unmarshal(body, jwks); err != nil {
		m.logger.Sugar().Errorf("Failed to parse response body: %s, err: %v", string(body), err)
		return nil
	}

	return jwks
}

func toString(v any) string {
	c, _ := json.Marshal(v)
	return string(c)
}

func (m CloudflareAuth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	jwtToken := r.Header.Get("Cf-Access-Jwt-Assertion")
	if len(jwtToken) == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}
	email := r.Header.Get("Cf-Access-Authenticated-User-Email")
	if len(email) == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	jwks := m.downloadPubKey(jwtToken)
	if jwks == nil || len(jwks.Keys) == 0 {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header is missing or invalid")
		}

		for _, key := range jwks.Keys {
			if key.Kid == kid {
				// Decode N and E
				nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
				if err != nil {
					return nil, fmt.Errorf("failed to decode N: %v", err)
				}

				eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
				if err != nil {
					return nil, fmt.Errorf("failed to decode E: %v", err)
				}

				// Convert E bytes to integer
				e := 0
				for _, b := range eBytes {
					e = e<<8 + int(b)
				}

				// Create the RSA public key
				n := new(big.Int).SetBytes(nBytes)
				rsaPublicKey := &rsa.PublicKey{
					N: n,
					E: e,
				}
				return rsaPublicKey, nil
			}
		}

		return nil, fmt.Errorf("unable to find key with kid: %s", kid)
	}

	token, err := jwt.ParseWithClaims(jwtToken, jwt.MapClaims{}, keyFunc, jwt.WithAudience(m.Aud))
	if err != nil {
		m.logger.Sugar().Errorf("Failed to verify JWT token: %s, err: %v", jwtToken, err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}
	if !token.Valid {
		m.logger.Sugar().Errorf("Invalid JWT token: %s, err: %v", toString(token), err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}
	if token.Claims.(jwt.MapClaims)["email"] != email {
		m.logger.Sugar().Errorf("Email not found in JWT token: %s, err: %v", toString(token), err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	next.ServeHTTP(w, r)

	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	if !h.Next() {
		return nil, h.ArgErr()
	}

	authHandler := &CloudflareAuth{}

	dispenser := h.NewFromNextSegment()
	for dispenser.Next() {
		for dispenser.NextBlock(0) {
			if dispenser.Nesting() != 1 {
				continue
			}

			switch dispenser.Val() {
			case "aud":
				if !dispenser.NextArg() {
					return nil, dispenser.ArgErr()
				}

				authHandler.Aud = dispenser.Val()

				dispenser.DeleteN(2)
			}
		}
	}
	dispenser.Reset()

	if authHandler.Aud == "" {
		return nil, dispenser.Errf("the 'aud' subdirective is required")
	}

	return authHandler, nil
}

var (
	_ caddy.Provisioner           = (*CloudflareAuth)(nil)
	_ caddyhttp.MiddlewareHandler = (*CloudflareAuth)(nil)
)
