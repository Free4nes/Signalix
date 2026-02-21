package config

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds the application configuration
type Config struct {
	DatabaseURL     string
	Port            string
	JWTSecret       string
	OTPSalt         string
	DevMode         bool
	AccessTokenTTL  time.Duration // default 15m
	RefreshTokenTTL time.Duration // default 720h (30 days)
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

	// Load ACCESS_TOKEN_TTL (optional, default 15m)
	cfg.AccessTokenTTL = 15 * time.Minute
	if v := os.Getenv("ACCESS_TOKEN_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.AccessTokenTTL = d
		}
	}

	// Load REFRESH_TOKEN_TTL (optional, default 720h)
	cfg.RefreshTokenTTL = 720 * time.Hour
	if v := os.Getenv("REFRESH_TOKEN_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.RefreshTokenTTL = d
		}
	} else if v := os.Getenv("REFRESH_TOKEN_TTL_HOURS"); v != "" {
		if h, err := strconv.Atoi(v); err == nil && h > 0 {
			cfg.RefreshTokenTTL = time.Duration(h) * time.Hour
		}
	}

	return cfg, nil
}
