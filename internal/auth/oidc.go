package auth

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	_ "crypto/sha512" // RS384/RS512/ES384
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"rgstr/internal/config"
)

// OpenID Connect sign-in for the web admin (authorization code flow with
// PKCE). Docker clients cannot follow a browser flow: OIDC users make a CLI
// secret in the admin and use it with docker login.

// ErrOIDC* explain a failed OIDC sign-in to the user.
var (
	ErrOIDCState    = errors.New("the sign-in expired or was started in another browser; try again")
	ErrOIDCDenied   = errors.New("your account is not in a group allowed to use this registry")
	ErrOIDCUsername = errors.New("the identity provider sent no usable user name")
)

type oidcAuth struct {
	cfg    config.OIDCConfig
	secret []byte // signs the state cookie
	client *http.Client

	mu     sync.Mutex
	disc   *oidcDiscovery
	discAt time.Time
	keys   map[string]crypto.PublicKey
	keysAt time.Time
}

type oidcDiscovery struct {
	Issuer   string `json:"issuer"`
	AuthURL  string `json:"authorization_endpoint"`
	TokenURL string `json:"token_endpoint"`
	JWKSURL  string `json:"jwks_uri"`
	UserInfo string `json:"userinfo_endpoint"`
}

func newOIDCAuth(cfg *config.Config) *oidcAuth {
	mac := hmac.New(sha256.New, []byte(cfg.AuthSecret))
	mac.Write([]byte("rgstr oidc state"))
	return &oidcAuth{cfg: cfg.OIDC, secret: mac.Sum(nil), client: &http.Client{Timeout: 15 * time.Second}}
}

// OIDCName is the provider's name for the sign-in button; "" when OIDC is off.
func (h *Handler) OIDCName() string {
	if h.oidc == nil || !h.cfg.AuthEnabled {
		return ""
	}
	return h.oidc.cfg.Name
}

// OIDCRedirectURL is the configured callback URL ("" = derive from the request).
func (h *Handler) OIDCRedirectURL() string { return h.cfg.OIDC.RedirectURL }

// oidcState travels in a signed cookie between the start of the sign-in
// and the callback.
type oidcState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Redirect string `json:"r"`
	Expires  int64  `json:"e"`
}

// OIDCBegin starts a sign-in: it returns the provider URL to send the
// browser to and the state to keep in a cookie.
func (h *Handler) OIDCBegin(ctx context.Context, redirectURL string) (authURL, cookie string, err error) {
	o := h.oidc
	d, err := o.discovery(ctx)
	if err != nil {
		return "", "", err
	}
	st := oidcState{State: randomString(), Nonce: randomString(), Verifier: randomString() + randomString(),
		Redirect: redirectURL, Expires: time.Now().Add(10 * time.Minute).Unix()}
	challenge := sha256.Sum256([]byte(st.Verifier))
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {o.cfg.ClientID},
		"redirect_uri":          {redirectURL},
		"scope":                 {strings.Join(o.cfg.Scopes, " ")},
		"state":                 {st.State},
		"nonce":                 {st.Nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(challenge[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(d.AuthURL, "?") {
		sep = "&"
	}
	return d.AuthURL + sep + q.Encode(), o.seal(st), nil
}

// OIDCFinish completes a sign-in from the provider's callback and opens a
// web admin session.
func (h *Handler) OIDCFinish(ctx context.Context, cookie, state, code string) (subject, token string, err error) {
	o := h.oidc
	st, ok := o.open(cookie)
	if !ok || state == "" || !hmac.Equal([]byte(st.State), []byte(state)) || time.Now().Unix() > st.Expires {
		return "", "", ErrOIDCState
	}
	d, err := o.discovery(ctx)
	if err != nil {
		return "", "", err
	}
	idToken, accessToken, err := o.exchange(ctx, d, code, st)
	if err != nil {
		return "", "", err
	}
	claims, err := o.verify(ctx, d, idToken, st.Nonce)
	if err != nil {
		return "", "", fmt.Errorf("id token: %w", err)
	}
	if _, has := claims[o.cfg.GroupsClaim]; !has && d.UserInfo != "" && accessToken != "" {
		// Some providers put groups only into the userinfo response.
		if info, err := o.userinfo(ctx, d, accessToken); err == nil && info["sub"] == claims["sub"] {
			for k, v := range info {
				if _, dup := claims[k]; !dup {
					claims[k] = v
				}
			}
		}
	}

	name := claimString(claims, o.cfg.UsernameClaim)
	if name == "" && o.cfg.UsernameClaim == "preferred_username" {
		name = claimString(claims, "email")
	}
	name = strings.ToLower(name)
	if name == "" || !externalNameRe.MatchString(name) {
		return "", "", ErrOIDCUsername
	}
	role, keepRole, allowed := roleForGroups(claimStrings(claims, o.cfg.GroupsClaim), o.cfg.Roles)
	if !allowed {
		return name, "", ErrOIDCDenied
	}
	if err := h.creds.signInExternal(name, SourceOIDC, role, keepRole); err != nil {
		return name, "", err
	}
	token, err = h.newSession(name)
	return name, token, err
}

func (o *oidcAuth) discovery(ctx context.Context) (*oidcDiscovery, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.disc != nil && time.Since(o.discAt) < time.Hour {
		return o.disc, nil
	}
	var d oidcDiscovery
	if err := o.getJSON(ctx, o.cfg.Issuer+"/.well-known/openid-configuration", "", &d); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	if strings.TrimSuffix(d.Issuer, "/") != o.cfg.Issuer {
		return nil, fmt.Errorf("oidc discovery: issuer is %q, RGSTR_OIDC_ISSUER is %q", d.Issuer, o.cfg.Issuer)
	}
	if d.AuthURL == "" || d.TokenURL == "" || d.JWKSURL == "" {
		return nil, errors.New("oidc discovery: endpoints missing")
	}
	o.disc, o.discAt = &d, time.Now()
	return o.disc, nil
}

func (o *oidcAuth) exchange(ctx context.Context, d *oidcDiscovery, code string, st oidcState) (idToken, accessToken string, err error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {st.Redirect},
		"code_verifier": {st.Verifier},
	}
	if o.cfg.ClientSecret == "" {
		form.Set("client_id", o.cfg.ClientID) // public client: PKCE only
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if o.cfg.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(o.cfg.ClientID), url.QueryEscape(o.cfg.ClientSecret))
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	var body struct {
		IDToken     string `json:"id_token"`
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
	if resp.StatusCode != http.StatusOK || body.IDToken == "" {
		return "", "", fmt.Errorf("token request: %s %s %s", resp.Status, body.Error, body.Description)
	}
	return body.IDToken, body.AccessToken, nil
}

func (o *oidcAuth) userinfo(ctx context.Context, d *oidcDiscovery, accessToken string) (map[string]any, error) {
	var info map[string]any
	err := o.getJSON(ctx, d.UserInfo, accessToken, &info)
	return info, err
}

// verify checks the ID token's signature, issuer, audience, expiry and nonce.
func (o *oidcAuth) verify(ctx context.Context, d *oidcDiscovery, raw, nonce string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeSegment(parts[0], &hdr); err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	key, err := o.key(ctx, d, hdr.Kid)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(hdr.Alg, key, []byte(parts[0]+"."+parts[1]), sig); err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := decodeSegment(parts[1], &claims); err != nil {
		return nil, err
	}
	if iss, _ := claims["iss"].(string); iss != d.Issuer {
		return nil, fmt.Errorf("issuer %q", iss)
	}
	auds := claimStrings(claims, "aud")
	if !contains(auds, o.cfg.ClientID) {
		return nil, errors.New("not issued for this client")
	}
	if azp, _ := claims["azp"].(string); len(auds) > 1 && azp != o.cfg.ClientID {
		return nil, errors.New("authorized party mismatch")
	}
	exp, _ := claims["exp"].(float64)
	if time.Now().Add(-time.Minute).Unix() > int64(exp) {
		return nil, errors.New("expired")
	}
	if n, _ := claims["nonce"].(string); !hmac.Equal([]byte(n), []byte(nonce)) {
		return nil, errors.New("nonce mismatch")
	}
	return claims, nil
}

// key returns the provider's signing key kid, refetching the key set when
// the key is unknown (providers rotate keys), at most once a minute.
func (o *oidcAuth) key(ctx context.Context, d *oidcDiscovery, kid string) (crypto.PublicKey, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	pick := func() crypto.PublicKey {
		if k, ok := o.keys[kid]; ok {
			return k
		}
		if kid == "" && len(o.keys) == 1 {
			for _, k := range o.keys {
				return k
			}
		}
		return nil
	}
	if k := pick(); k != nil {
		return k, nil
	}
	if time.Since(o.keysAt) < time.Minute {
		return nil, fmt.Errorf("unknown signing key %q", kid)
	}
	var set struct {
		Keys []struct {
			Kty, Kid, Use, Crv, N, E, X, Y string
		} `json:"keys"`
	}
	if err := o.getJSON(ctx, d.JWKSURL, "", &set); err != nil {
		return nil, fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if pub := parseJWK(k.Kty, k.Crv, k.N, k.E, k.X, k.Y); pub != nil {
			keys[k.Kid] = pub
		}
	}
	o.keys, o.keysAt = keys, time.Now()
	if k := pick(); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("unknown signing key %q", kid)
}

func parseJWK(kty, crv, n, e, x, y string) crypto.PublicKey {
	b := func(s string) *big.Int {
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil || len(raw) == 0 {
			return nil
		}
		return new(big.Int).SetBytes(raw)
	}
	switch kty {
	case "RSA":
		nn, ee := b(n), b(e)
		if nn == nil || ee == nil || !ee.IsInt64() {
			return nil
		}
		return &rsa.PublicKey{N: nn, E: int(ee.Int64())}
	case "EC":
		var c elliptic.Curve
		switch crv {
		case "P-256":
			c = elliptic.P256()
		case "P-384":
			c = elliptic.P384()
		default:
			return nil
		}
		xx, yy := b(x), b(y)
		if xx == nil || yy == nil {
			return nil
		}
		return &ecdsa.PublicKey{Curve: c, X: xx, Y: yy}
	}
	return nil
}

func verifySignature(alg string, key crypto.PublicKey, signed, sig []byte) error {
	var h crypto.Hash
	switch alg {
	case "RS256", "PS256", "ES256":
		h = crypto.SHA256
	case "RS384", "PS384", "ES384":
		h = crypto.SHA384
	case "RS512", "PS512":
		h = crypto.SHA512
	default:
		return fmt.Errorf("unsupported algorithm %q", alg) // never "none" or HMAC
	}
	hasher := h.New()
	hasher.Write(signed)
	digest := hasher.Sum(nil)
	bad := errors.New("bad signature")
	switch k := key.(type) {
	case *rsa.PublicKey:
		var err error
		if alg[0] == 'P' {
			err = rsa.VerifyPSS(k, h, digest, sig, nil)
		} else if alg[0] == 'R' {
			err = rsa.VerifyPKCS1v15(k, h, digest, sig)
		} else {
			err = bad
		}
		if err != nil {
			return bad
		}
		return nil
	case *ecdsa.PublicKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		if alg[0] != 'E' || len(sig) != 2*size {
			return bad
		}
		r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, digest, r, s) {
			return bad
		}
		return nil
	}
	return bad
}

func (o *oidcAuth) getJSON(ctx context.Context, u, bearer string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// seal and open sign the state cookie, so it cannot be forged.
func (o *oidcAuth) seal(st oidcState) string {
	raw, _ := json.Marshal(st)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, o.secret)
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (o *oidcAuth) open(cookie string) (oidcState, bool) {
	payload, sig, ok := strings.Cut(cookie, ".")
	if !ok {
		return oidcState{}, false
	}
	mac := hmac.New(sha256.New, o.secret)
	mac.Write([]byte(payload))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	var st oidcState
	if !hmac.Equal([]byte(sig), []byte(want)) || decodeSegment(payload, &st) != nil {
		return oidcState{}, false
	}
	return st, true
}

func decodeSegment(seg string, v any) error {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func randomString() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func claimString(c map[string]any, name string) string {
	s, _ := c[name].(string)
	return strings.TrimSpace(s)
}

// claimStrings reads a claim that is a string or a list of strings.
func claimStrings(c map[string]any, name string) []string {
	switch v := c[name].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
