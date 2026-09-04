package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/signal"
	"servicea/internal/config"
	"strings"
	"syscall"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
)

var cfg config.Config
var jwks keyfunc.Keyfunc

func initJWKS(cfg config.Config) {
	jwksUrl := cfg.KEYCLOAK_BASE_URL + "/realms/" + cfg.REALM + "/protocol/openid-connect/certs"

	var err error

	jwks, err = keyfunc.NewDefaultCtx(context.Background(), []string{jwksUrl})

	if err != nil {
		log.Fatalf("Failed to Init jwk: %v", err)
	}
}

func AuthMiddleware(next http.Handler) http.Handler {
	expectedIssuer := cfg.KEYCLOAK_BASE_URL + "/realms/" + cfg.REALM

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		if tokenStr == "" {
			http.Error(w, "Missing Bearer token", http.StatusUnauthorized)
			return
		}

		fmt.Println(tokenStr)
		token, err := jwt.Parse(tokenStr, jwks.Keyfunc)
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)

		if !ok {
			http.Error(w, "Invalid claims", http.StatusUnauthorized)
			return
		}

		if iss, _ := claims["iss"].(string); iss != expectedIssuer {
			http.Error(w, "Untrusted issuer", http.StatusUnauthorized)
			return
		}

		if !audMatches(claims["aud"], "serviceb") {
			http.Error(w, "Invalid Audience", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), "claims", claims)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
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

func getResourceHandler(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(jwt.MapClaims)

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)

	res := map[string]interface{}{
		"message":  "Hello",
		"email":    email,
		"userName": sub,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	cfg = config.LoadFromEnv()
	initJWKS(cfg)

	r := chi.NewRouter()
	r.Group(func(protected chi.Router) {
		protected.Use(AuthMiddleware)
		protected.Get("/api/resource", getResourceHandler)
	})

	go func() {
		log.Println("ServiceA server listening on 3000")
		log.Fatal(http.ListenAndServe(":3000", r))
		fmt.Println("This should not be logged")
	}()

	<-ctx.Done()
	log.Println("shutdown signal received")
}
