package overlord

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// CloudBar permission codes (cloudbar/backend/src/constants/permissionConstant.js).
const (
	permView = "overlord$view"
	permEdit = "overlord$edit"

	accessCookie  = "ovl_token"
	refreshCookie = "ovl_refresh"

	cbCacheTTL      = 60 * time.Second
	cbRefreshReuse  = 30 * time.Second
	cbRequestTimout = 5 * time.Second
)

var errCBExpired = errors.New("token expired")
var errCBDenied = errors.New("token rejected")

type cbUser struct {
	name  string
	perms []string
	until time.Time // cache expiry
}

func (u *cbUser) can(perm string) bool {
	for _, p := range u.perms {
		if p == perm || (perm == permView && p == permEdit) {
			return true
		}
	}
	return false
}

type cbTokens struct {
	access, refresh string
	at              time.Time
}

// Auth guards HTTP handlers. A CloudBar access token (Bearer header or
// cookie) is checked against CloudBar's /me endpoint, the same way
// demand-plan-auth does it, so Overlord never holds CloudBar's signing key.
// htpasswd basic auth stays as a fallback for the ovl CLI.
type Auth struct {
	cbAPI  string // e.g. https://api.dev.botrista.io; empty disables CloudBar auth
	cbWeb  string // e.g. https://cloudbar.dev.botrista.io
	basic  *BasicAuth
	open   bool // -no-auth
	client *http.Client

	mu    sync.Mutex
	cache map[string]*cbUser // sha256(access token) -> user

	// CloudBar rotates refresh tokens on use; a page load fires many requests
	// at once, so refreshes are serialized and the result reused briefly.
	// ponytail: one global lock, fine at Overlord's user count.
	refreshMu sync.Mutex
	refreshed map[string]cbTokens // sha256(old refresh token) -> new pair
}

// NewAuth creates the request authorizer.
func NewAuth(cbAPI, cbWeb string, basic *BasicAuth, open bool) *Auth {
	return &Auth{
		cbAPI:     strings.TrimRight(cbAPI, "/"),
		cbWeb:     strings.TrimRight(cbWeb, "/"),
		basic:     basic,
		open:      open,
		client:    &http.Client{Timeout: cbRequestTimout},
		cache:     make(map[string]*cbUser),
		refreshed: make(map[string]cbTokens),
	}
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return string(sum[:])
}

// cbCall sends an authenticated request to CloudBar and decodes `data`.
func (a *Auth) cbCall(method, path, token string, out interface{}) error {
	req, err := http.NewRequest(method, a.cbAPI+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		return errCBExpired
	case res.StatusCode >= 500:
		return errors.New("cloudbar: " + res.Status)
	case res.StatusCode != http.StatusOK:
		return errCBDenied
	}
	return json.NewDecoder(res.Body).Decode(&struct {
		Data interface{} `json:"data"`
	}{out})
}

// verify returns the CloudBar user for an access token.
func (a *Auth) verify(token string) (*cbUser, error) {
	key := hashToken(token)
	a.mu.Lock()
	u, ok := a.cache[key]
	a.mu.Unlock()
	if ok && time.Now().Before(u.until) {
		return u, nil
	}

	var me struct {
		UserName string `json:"user_name"`
	}
	if err := a.cbCall("GET", "/me", token, &me); err != nil {
		return nil, err
	}

	// CloudBar accepted this exact token, so its payload can be trusted.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errCBDenied
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, errCBDenied
	}
	var claims struct {
		Permissions []string `json:"permissions"`
		Exp         int64    `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, errCBDenied
	}

	until := time.Now().Add(cbCacheTTL)
	if exp := time.Unix(claims.Exp, 0); claims.Exp > 0 && exp.Before(until) {
		until = exp
	}
	u = &cbUser{name: me.UserName, perms: claims.Permissions, until: until}

	a.mu.Lock()
	// ponytail: full sweep on insert, fine for hundreds of tokens.
	for k, v := range a.cache {
		if time.Now().After(v.until) {
			delete(a.cache, k)
		}
	}
	a.cache[key] = u
	a.mu.Unlock()
	return u, nil
}

// refresh trades a refresh token for a new token pair, at most once.
func (a *Auth) refresh(rt string) (cbTokens, error) {
	a.refreshMu.Lock()
	defer a.refreshMu.Unlock()

	key := hashToken(rt)
	if t, ok := a.refreshed[key]; ok && time.Since(t.at) < cbRefreshReuse {
		return t, nil
	}
	for k, t := range a.refreshed {
		if time.Since(t.at) >= cbRefreshReuse {
			delete(a.refreshed, k)
		}
	}

	var res struct {
		AccessToken  string `json:"accessToken"`
		RefreshToken string `json:"refreshToken"`
	}
	if err := a.cbCall("POST", "/refresh", rt, &res); err != nil {
		return cbTokens{}, err
	}
	t := cbTokens{res.AccessToken, res.RefreshToken, time.Now()}
	a.refreshed[key] = t
	return t, nil
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func setTokenCookies(w http.ResponseWriter, r *http.Request, access, refresh string) {
	for name, value := range map[string]string{accessCookie: access, refreshCookie: refresh} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    value,
			Path:     "/",
			MaxAge:   7 * 24 * 3600, // CloudBar refresh TTL; access expiry is checked by CloudBar
			HttpOnly: true,
			Secure:   isHTTPS(r),
			SameSite: http.SameSiteLaxMode, // Overlord is iframed from CloudBar on the same site
		})
	}
}

// cbUserFromRequest authenticates via Bearer header or cookies, refreshing
// an expired cookie session transparently.
func (a *Auth) cbUserFromRequest(w http.ResponseWriter, r *http.Request) (*cbUser, error) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return a.verify(strings.TrimPrefix(h, "Bearer "))
	}
	c, err := r.Cookie(accessCookie)
	if err != nil {
		return nil, errCBDenied
	}
	u, err := a.verify(c.Value)
	if err != errCBExpired {
		return u, err
	}
	rc, err := r.Cookie(refreshCookie)
	if err != nil {
		return nil, errCBExpired
	}
	t, err := a.refresh(rc.Value)
	if err != nil {
		return nil, err
	}
	setTokenCookies(w, r, t.access, t.refresh)
	return a.verify(t.access)
}

func (a *Auth) loginURL(r *http.Request) string {
	scheme := "http"
	if isHTTPS(r) {
		scheme = "https"
	}
	callback := scheme + "://" + r.Host + "/auth/callback?next=" + url.QueryEscape(r.URL.RequestURI())
	return a.cbWeb + "/login?redirect=" + url.QueryEscape(callback)
}

func wantsHTML(r *http.Request) bool {
	return r.Method == "GET" && r.Header.Get("Upgrade") == "" &&
		strings.Contains(r.Header.Get("Accept"), "text/html")
}

func mustJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func audit(r *http.Request, user, perm, result string) {
	log.Printf("AUDIT %s", mustJSON(map[string]string{
		"user":   user,
		"ip":     getRequestIP(r),
		"method": r.Method,
		"path":   r.URL.Path,
		"query":  r.URL.RawQuery, // shell `command`, forward host/port, tty device
		"perm":   perm,
		"result": result,
	}))
}

// Wrap guards h with the given CloudBar permission (permView or permEdit).
// Edit-level requests and every denial are written to the AUDIT log.
func (a *Auth) Wrap(h http.Handler, perm string) http.Handler {
	if a.open {
		return h
	}
	pass := func(w http.ResponseWriter, r *http.Request, user string) {
		if perm == permEdit {
			audit(r, user, perm, "ok")
		}
		h.ServeHTTP(w, r)
	}
	basic := a.basic.WrapHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, _, _ := r.BasicAuth()
		pass(w, r, "htpasswd:"+user)
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, hasBasic := r.BasicAuth()
		if a.cbAPI == "" || (hasBasic && !a.basic.Disable) {
			basic.ServeHTTP(w, r)
			return
		}

		u, err := a.cbUserFromRequest(w, r)
		switch {
		case err == nil && u.can(perm):
			pass(w, r, u.name)
		case err == nil:
			audit(r, u.name, perm, "forbidden")
			http.Error(w, "Forbidden: missing CloudBar permission "+perm, http.StatusForbidden)
		case err == errCBExpired || err == errCBDenied:
			if wantsHTML(r) {
				http.Redirect(w, r, a.loginURL(r), http.StatusFound)
				return
			}
			audit(r, "", perm, "unauthorized")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		default:
			log.Printf("Auth: CloudBar unavailable: %s", err)
			http.Error(w, "CloudBar unavailable", http.StatusBadGateway)
		}
	})
}

// CallbackHandler receives ?token&refreshToken from CloudBar's
// /login?redirect= flow and stores them as cookies.
func (a *Auth) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	token, refresh := q.Get("token"), q.Get("refreshToken")
	u, err := a.verify(token)
	if err != nil {
		http.Error(w, "Unauthorized: invalid CloudBar token", http.StatusUnauthorized)
		return
	}
	next := q.Get("next")
	// Only local paths: no open redirect.
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		next = "/"
	}
	setTokenCookies(w, r, token, refresh)
	log.Printf("AUDIT %s", mustJSON(map[string]string{ // not audit(): the query holds the tokens
		"user": u.name, "ip": getRequestIP(r), "path": r.URL.Path, "perm": "login", "result": "ok"}))
	http.Redirect(w, r, next, http.StatusFound)
}
