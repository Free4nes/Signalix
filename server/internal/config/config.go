package config

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
)

// Config holds the application configuration
type Config struct {
	DatabaseURL string
	Port        string
	JWTSecret   string
	OTPSalt     string
	DevMode     bool
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Port: "8080", // default port
	}

	// Load DATABASE_URL and log connection details (password masked)
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable is required")
	}
	cfg.DatabaseURL = databaseURL

	if u, err := url.Parse(databaseURL); err == nil {
		host := u.Hostname()
		if host == "" {
			host = "localhost"
		}
		port := u.Port()
		if port == "" {
			port = "5432"
		}
		dbName := strings.TrimPrefix(u.Path, "/")
		if idx := strings.Index(dbName, "?"); idx >= 0 {
			dbName = dbName[:idx]
		}
		user := u.User.Username()
		if user == "" {
			user = "(none)"
		}
		log.Printf("DB connect: host=%s port=%s db=%s user=%s", host, port, dbName, user)
	}

	// Load PORT (optional, defaults to 8080)
	if port := os.Getenv("PORT"); port != "" {
		cfg.Port = port
	}

	// Load JWT_SECRET (required)
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET environment variable is required")
	}
	cfg.JWTSecret = jwtSecret

	// Load OTP_SALT (required)
	otpSalt := os.Getenv("OTP_SALT")
	if otpSalt == "" {
		return nil, fmt.Errorf("OTP_SALT environment variable is required")
	}
	cfg.OTPSalt = otpSalt

	// Load DEV_MODE (optional, defaults to false)
	devMode := os.Getenv("DEV_MODE")
	cfg.DevMode = devMode == "true"

	return cfg, nil
}
