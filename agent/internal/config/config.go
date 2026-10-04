// Package config defines the Sentinel agent's on-disk configuration model and
// its load/save behaviour. Configuration is explicit and typed; defaults are
// conservative (loopback-only listener, short auth windows) so that a
// misconfigured agent fails safe rather than exposing a wide surface.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Config is the complete agent configuration.
type Config struct {
	// DeviceName overrides the host name reported to the Operator. Empty means
	// use the real host name.
	DeviceName string `json:"deviceName"`

	// Listen is the address the control API binds to. The default is loopback
	// only; remote reachability is provided by a private overlay network
	// (spec §3), never by binding to a public interface here.
	Listen string `json:"listen"`

	// DataDir is the root for persistent agent state (device registry, admin
	// key, logs).
	DataDir string `json:"dataDir"`

	// AdminLoopbackOnly restricts owner/admin endpoints (pairing initiation and
	// device management) to requests originating from the local machine, so
	// pairing and revocation can only be driven by someone with local access to
	// the Windows host even when the control API is reachable over the overlay
	// network. Default true.
	AdminLoopbackOnly bool `json:"adminLoopbackOnly"`

	Panic   PanicConfig   `json:"panic"`
	Auth    AuthConfig    `json:"auth"`
	Pairing PairingConfig `json:"pairing"`
	Log     LogConfig     `json:"log"`
}

// PairingConfig tunes the device pairing window (spec §13).
type PairingConfig struct {
	// TTL is how long an owner-initiated pairing window stays open.
	TTL Duration `json:"ttl"`
}

// PanicConfig configures the PANIC preset (spec §7).
type PanicConfig struct {
	// CloseApps lists executable image names closed by PANIC, in order.
	CloseApps []string `json:"closeApps"`
}

// AuthConfig tunes request authentication (spec §13).
type AuthConfig struct {
	// TimestampSkew is the maximum age/future-dating allowed for a signed
	// request. Requests outside this window are rejected as expired/replayed.
	TimestampSkew Duration `json:"timestampSkew"`
}

// LogConfig configures audit logging (spec §12).
type LogConfig struct {
	// RetentionDays is how many days of daily log files to keep. Zero disables
	// automatic deletion.
	RetentionDays int `json:"retentionDays"`
}

// LogsDir returns the directory holding daily audit log files.
func (c Config) LogsDir() string { return filepath.Join(c.DataDir, "Logs") }

// DevicesPath returns the file holding the authorized-device registry.
func (c Config) DevicesPath() string { return filepath.Join(c.DataDir, "devices.json") }

// AdminKeyPath returns the file holding the protected owner/admin key.
func (c Config) AdminKeyPath() string { return filepath.Join(c.DataDir, "admin.key") }

// DefaultConfigPath returns the default location of the agent's config file.
func DefaultConfigPath() string { return filepath.Join(defaultDataDir(), "config.json") }

// Default returns a configuration with safe defaults for the current host.
func Default() Config {
	return Config{
		DeviceName:        "",
		Listen:            "127.0.0.1:8787",
		DataDir:           defaultDataDir(),
		AdminLoopbackOnly: true,
		Panic:             PanicConfig{CloseApps: []string{}},
		Auth:              AuthConfig{TimestampSkew: Duration(30 * time.Second)},
		Pairing:           PairingConfig{TTL: Duration(5 * time.Minute)},
		Log:               LogConfig{RetentionDays: 30},
	}
}

// defaultDataDir returns the platform-appropriate persistent data directory.
// On Windows this is C:\ProgramData\Sentinel (spec §10).
func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "Sentinel")
		}
		return `C:\ProgramData\Sentinel`
	}
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "sentinel")
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".local", "state", "sentinel")
	}
	return filepath.Join(os.TempDir(), "sentinel")
}

// Load reads configuration from path. If the file does not exist, a default
// configuration is written to path and returned, so first run is self-seeding.
// Unknown fields in the file are rejected to catch typos rather than silently
// ignoring intended settings.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		cfg := Default()
		if err := Save(path, cfg); err != nil {
			return Config{}, fmt.Errorf("seed default config: %w", err)
		}
		return cfg, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("read config %s: %w", path, err)
	}

	cfg := Default()
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return Config{}, fmt.Errorf("invalid config %s: %w", path, err)
	}
	return cfg, nil
}

// Save writes cfg to path as indented JSON, creating parent directories.
func Save(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func (c Config) validate() error {
	if c.Listen == "" {
		return fmt.Errorf("listen address must not be empty")
	}
	if c.DataDir == "" {
		return fmt.Errorf("dataDir must not be empty")
	}
	if time.Duration(c.Auth.TimestampSkew) <= 0 {
		return fmt.Errorf("auth.timestampSkew must be positive")
	}
	if time.Duration(c.Pairing.TTL) <= 0 {
		return fmt.Errorf("pairing.ttl must be positive")
	}
	if c.Log.RetentionDays < 0 {
		return fmt.Errorf("log.retentionDays must not be negative")
	}
	return nil
}
