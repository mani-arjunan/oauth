package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

var (
	keycloakBaseURL = getEnv("KEYCLOAK_BASE_URL", "http://localhost:8080")
	realm           = getEnv("KEYCLOAK_REALM", "servicea")
	clientID        = getEnv("CLIENT_ID", "serviceb")
	clientSecret    = getEnv("CLIENT_SECRET", "wTctosmQ9HUdPbjPfKv4Ln4j9NYSJuEi")
	redirectURI     = getEnv("REDIRECT_URI", "http://localhost:4000/auth/callback")

	authEndpoint  string
	tokenEndpoint string
	jwksURL       string
	issuer        string
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func initOIDCEndpoints() {
	issuer = keycloakBaseURL + "/realms/" + realm
	authEndpoint = issuer + "/protocol/openid-connect/auth"
	tokenEndpoint = issuer + "/protocol/openid-connect/token"
	jwksURL = issuer + "/protocol/openid-connect/certs"
}

var jwks keyfunc.Keyfunc

func initJWKS() {
	var err error
	jwks, err = keyfunc.NewDefaultCtx(context.Background(), []string{jwksURL})
	if err != nil {
		log.Fatalf("failed to init jwks: %v", err)
	}
}

var tmpl = template.Must(template.ParseGlob("templates/*.html"))

type pendingAuth struct {
	verifier string
	state    string
}

var (
	pendingMu sync.Mutex
	pending   = map[string]pendingAuth{}
)

type session struct {
	sub   string
	email string
}

var (
	sessionMu sync.Mutex
	sessions  = map[string]session{}
)

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	verifier := randomString(32)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	state := randomString(16)

	sessID := randomString(16)
	pendingMu.Lock()
	pending[sessID] = pendingAuth{verifier: verifier, state: state}
	pendingMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name: "pending_auth", Value: sessID, HttpOnly: true, Path: "/", MaxAge: 300,
	})

	params := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	http.Redirect(w, r, authEndpoint+"?"+params.Encode(), http.StatusFound)
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	c, err := r.Cookie("pending_auth")
	if err != nil {
		http.Error(w, "missing pending auth cookie", http.StatusBadRequest)
		return
	}

	pendingMu.Lock()
	pa, ok := pending[c.Value]
	delete(pending, c.Value)
	pendingMu.Unlock()

	if !ok || pa.state != state {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code_verifier": {pa.verifier},
	}

	req, _ := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		http.Error(w, "token exchange rejected: "+string(b), http.StatusUnauthorized)
		return
	}

	var tr struct {
		IDToken string `json:"id_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tr)


	fmt.Println(tr.IDToken)
	claims, err := validateIDToken(tr.IDToken)
	if err != nil {
		http.Error(w, "invalid id_token: "+err.Error(), http.StatusUnauthorized)
		return
	}

	sub, _ := claims["preferred_username"].(string)
	email, _ := claims["email"].(string)

	sessID := randomString(24)
	sessionMu.Lock()
	sessions[sessID] = session{sub: sub, email: email}
	sessionMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name: "session", Value: sessID, HttpOnly: true, Path: "/", MaxAge: 86400,
	})
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func validateIDToken(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, jwks.Keyfunc)
	if err != nil || !token.Valid {
		return nil, err
	}

	claims := token.Claims.(jwt.MapClaims)
	if claims["iss"] != issuer {
		return nil, jwt.ErrTokenInvalidIssuer
	}
	if !audMatches(claims["aud"], clientID) {
		return nil, jwt.ErrTokenInvalidAudience
	}
	return claims, nil
}

func audMatches(aud interface{}, expected string) bool {
	switch v := aud.(type) {
	case string:
		return v == expected
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	sessionMu.Lock()
	sess, ok := sessions[c.Value]
	sessionMu.Unlock()

	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	tmpl.ExecuteTemplate(w, "dashboard.html", map[string]string{
		"Sub":   sess.sub,
		"Email": sess.email,
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err == nil {
		sessionMu.Lock()
		delete(sessions, c.Value)
		sessionMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl.ExecuteTemplate(w, "login.html", nil)
}

func main() {
	initOIDCEndpoints()
	initJWKS()

	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/auth/login", loginHandler)
	http.HandleFunc("/auth/callback", callbackHandler)
	http.HandleFunc("/dashboard", dashboardHandler)
	http.HandleFunc("/auth/logout", logoutHandler)

	log.Println("Company B app on :4000")
	log.Fatal(http.ListenAndServe(":4000", nil))
}
