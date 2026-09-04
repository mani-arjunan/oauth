package config

import "os"

type Config struct {
	KEYCLOAK_BASE_URL string
	REALM             string
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return fallback
}

func LoadFromEnv() Config {
	config := Config{
		KEYCLOAK_BASE_URL: getEnv("KEYCLOAK_BASE_URL", "http://localhost:8080"),
		REALM:             getEnv("REALM", "servicea"),
	}

	return config
}
