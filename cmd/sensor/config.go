// Daemon configuration (M1.1). A JSON file with graceful defaults — a PoC
// daemon should run with zero required setup. See packaging/sensor.json.example.
package main

import (
	"encoding/json"
	"log/slog"
	"os"
	"strings"
)

// Config is the on-disk daemon configuration.
type Config struct {
	CgroupPath string `json:"cgroup_path"`
	LogLevel   string `json:"log_level"`
}

func defaultConfig() Config {
	return Config{
		CgroupPath: "/sys/fs/cgroup",
		LogLevel:   "info",
	}
}

// loadConfig reads path if present; a missing file is not an error (the
// daemon runs on defaults) — a malformed one is.
func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
