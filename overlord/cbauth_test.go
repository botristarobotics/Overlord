package overlord

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fakeJWT(user string, perms ...string) string {
	p, _ := json.Marshal(map[string]interface{}{
		"user_name": user, "permissions": perms, "exp": time.Now().Add(time.Hour).Unix()})
	return "h." + base64.RawURLEncoding.EncodeToString(p) + ".s"
}

func TestAuthWrap(t *testing.T) {
	editTok, viewTok, noneTok := fakeJWT("eng", permEdit), fakeJWT("ops", permView), fakeJWT("guest")
	expiredTok, newTok := fakeJWT("eng-old", permEdit), fakeJWT("eng", permEdit)
	var refreshCalls int32

	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case r.URL.Path == "/me" && tok == expiredTok:
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/me" && (tok == editTok || tok == viewTok || tok == noneTok || tok == newTok):
			w.Write([]byte(`{"status":true,"data":{"user_name":"u"}}`))
		case r.URL.Path == "/refresh" && tok == "rt1":
			atomic.AddInt32(&refreshCalls, 1)
			w.Write([]byte(`{"data":{"accessToken":"` + newTok + `","refreshToken":"rt2"}}`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer cb.Close()

	a := NewAuth(cb.URL, "https://cloudbar.example", &BasicAuth{Disable: true}, false)
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	view, edit := a.Wrap(ok, permView), a.Wrap(ok, permEdit)

	do := func(h http.Handler, hdr map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/agent/tty/m1", nil)
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	bearer := func(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

	cases := []struct {
		name string
		got  int
		want int
	}{
		{"edit token, edit route", do(edit, bearer(editTok)).Code, 200},
		{"view token, view route", do(view, bearer(viewTok)).Code, 200},
		{"view token, edit route", do(edit, bearer(viewTok)).Code, 403},
		{"no permission token", do(view, bearer(noneTok)).Code, 403},
		{"forged token", do(view, bearer(fakeJWT("evil", permEdit))).Code, 401},
		{"no token, API", do(view, nil).Code, 401},
		{"no token, browser", do(view, map[string]string{"Accept": "text/html"}).Code, 302},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, c.got, c.want)
		}
	}

	// Expired cookie session refreshes once, even with concurrent requests.
	done := make(chan *httptest.ResponseRecorder, 5)
	for i := 0; i < 5; i++ {
		go func() {
			done <- do(edit, nil, &http.Cookie{Name: accessCookie, Value: expiredTok},
				&http.Cookie{Name: refreshCookie, Value: "rt1"})
		}()
	}
	for i := 0; i < 5; i++ {
		w := <-done
		if w.Code != 200 || !strings.Contains(w.Header().Get("Set-Cookie"), newTok) &&
			!strings.Contains(strings.Join(w.Header()["Set-Cookie"], ";"), newTok) {
			t.Errorf("refresh: code %d, cookies %v", w.Code, w.Header()["Set-Cookie"])
		}
	}
	if n := atomic.LoadInt32(&refreshCalls); n != 1 {
		t.Errorf("refresh called %d times, want 1", n)
	}

	// Callback: sets cookies, rejects open redirects.
	r := httptest.NewRequest("GET", "/auth/callback?token="+editTok+"&refreshToken=rt9&next=//evil.com", nil)
	w := httptest.NewRecorder()
	a.CallbackHandler(w, r)
	if w.Code != 302 || w.Header().Get("Location") != "/" || len(w.Header()["Set-Cookie"]) != 2 {
		t.Errorf("callback: code %d, location %q, cookies %v", w.Code, w.Header().Get("Location"), w.Header()["Set-Cookie"])
	}
}
