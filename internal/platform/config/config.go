package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	// empty = not configured; a set value is operator intent, never second-guessed
	ProxyBaseURL string
	APIKey       string
	Model        string
	Provider     string // "anthropic" | "openai"; empty infers from Model
	DataDir      string
	DockerBin    string
	AgentImage   string // empty = the agent runs on the host

	// empty StrongModel = no tiering; empty Strong{Provider,BaseURL,Key} fall back
	StrongModel    string
	StrongProvider string
	StrongBaseURL  string
	StrongKey      string
}

func Defaults() Config {
	return Config{
		// no default: empty is the "unset" sentinel an explicit endpoint must outrank
		ProxyBaseURL:   os.Getenv("QUARRY_PROXY_URL"),
		APIKey:         env("QUARRY_API_KEY", os.Getenv("OPENAI_API_KEY")),
		Model:          env("QUARRY_MODEL", "glm-5.2-ant"),
		Provider:       os.Getenv("QUARRY_PROVIDER"),
		DataDir:        env("QUARRY_HOME", defaultDataDir()),
		DockerBin:      os.Getenv("QUARRY_DOCKER_BIN"),
		AgentImage:     os.Getenv("QUARRY_AGENT_IMAGE"),
		StrongModel:    os.Getenv("QUARRY_MODEL_STRONG"),
		StrongProvider: os.Getenv("QUARRY_PROVIDER_STRONG"),
		StrongBaseURL:  os.Getenv("QUARRY_MODEL_STRONG_URL"),
		StrongKey:      os.Getenv("QUARRY_MODEL_STRONG_KEY"),
	}
}

const (
	defaultProxyURL = "http://127.0.0.1:4000/v1"
	anthropicAPIURL = "https://api.anthropic.com/v1"
)

func inferProvider(provider, model string) string {
	if provider != "" {
		return provider
	}
	if strings.HasSuffix(model, "-ant") || strings.HasPrefix(model, "claude") {
		return "anthropic"
	}
	return "openai"
}

// "-ant" is a wire format, not a host: never route its key to Anthropic
func wireOnlyAnthropic(provider, model string) bool {
	return provider == "" && strings.HasSuffix(model, "-ant") && !strings.HasPrefix(model, "claude")
}

// an explicit URL is authoritative even when it equals defaultProxyURL
func endpointFor(explicitURL, sharedProxyURL, provider, model string) string {
	if explicitURL != "" {
		return explicitURL
	}
	if inferProvider(provider, model) == "anthropic" && !wireOnlyAnthropic(provider, model) {
		return anthropicAPIURL
	}
	if sharedProxyURL != "" {
		return sharedProxyURL
	}
	return defaultProxyURL
}

func (c Config) ResolvedProvider() string { return inferProvider(c.Provider, c.Model) }

func (c Config) ModelBaseURL() string {
	return endpointFor(c.ProxyBaseURL, "", c.Provider, c.Model)
}

func (c Config) StrongResolvedProvider() string {
	if c.StrongProvider != "" {
		return c.StrongProvider
	}
	if c.StrongModel != "" {
		return inferProvider("", c.StrongModel)
	}
	return c.ResolvedProvider()
}

// never inherits the default tier's endpoint when that points at another provider
func (c Config) StrongModelBaseURL() string {
	if c.StrongBaseURL == "" && c.StrongProvider == "" && c.StrongModel == "" {
		return c.ModelBaseURL()
	}
	return endpointFor(c.StrongBaseURL, c.ProxyBaseURL, c.StrongProvider, c.StrongModel)
}

// provider alone is not enough: one wire format can mean two hosts
func (c Config) strongHostDiffers() bool {
	return c.StrongResolvedProvider() != c.ResolvedProvider() ||
		c.StrongModelBaseURL() != c.ModelBaseURL()
}

// never inherit a key across hosts; cross-host with no key of its own yields ""
func (c Config) StrongAPIKey() string {
	if c.StrongKey != "" {
		return c.StrongKey
	}
	if c.strongHostDiffers() {
		return ""
	}
	return c.APIKey
}

// callers must refuse the strong transport rather than cross-authenticate
func (c Config) StrongKeyMissing() bool {
	return c.StrongModel != "" && c.StrongKey == "" && c.strongHostDiffers()
}

func (c Config) StrongTransportDiffers() bool {
	return c.strongHostDiffers() || c.StrongAPIKey() != c.APIKey
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".quarry"
	}
	return filepath.Join(home, ".quarry")
}

func (c Config) StoreDir() string { return filepath.Join(c.DataDir, "store") }

func (c Config) WorkspaceDir() string { return filepath.Join(c.DataDir, "ws") }

func (c Config) EnsureDataDir() error {
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return err
	}
	return os.Chmod(c.DataDir, 0o700)
}

// atomic via hard link: never a half-written identity (vault: Store and Config)
func (c Config) LoadOrCreateSigningKey() (ed25519.PrivateKey, error) {
	if err := c.EnsureDataDir(); err != nil {
		return nil, err
	}
	keyPath := filepath.Join(c.DataDir, "client.key")

	for attempt := 0; ; attempt++ {
		key, found, err := readSigningKey(keyPath)
		if err != nil {
			return nil, err
		}
		if found {
			return key, nil
		}
		if attempt > 0 {
			// lost the link race, then the winner's key vanished: refuse rather than spin
			return nil, fmt.Errorf("config: client key %s disappeared while being created; re-run", keyPath)
		}
		claimed, err := mintSigningKey(keyPath)
		if err != nil {
			return nil, err
		}
		if claimed != nil {
			return claimed, nil
		}
		// claimed concurrently: the winner's key is authoritative, so re-read
	}
}

// found=false only when the file is absent; never re-mint on an ambiguous error
func readSigningKey(path string) (ed25519.PrivateKey, bool, error) {
	info, err := os.Stat(path)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrNotExist):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("config: cannot access client key %s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, false, fmt.Errorf("config: client key %s has insecure permissions %o; chmod 600 it (a shared key can forge signed patterns)", path, info.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil // removed between stat and read
	}
	if err != nil {
		return nil, false, err
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		// do not remove it here: it could be a key a racing run is linking in
		return nil, false, fmt.Errorf("config: client key %s is empty (interrupted write); it holds no identity — delete it and re-run", path)
	}
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, false, fmt.Errorf("config: corrupt client key at %s", path)
	}
	return ed25519.PrivateKey(raw), true, nil
}

// os.Link fails EEXIST rather than clobbering; (nil, nil) means adopt the existing key
func mintSigningKey(path string) (ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// same dir: the link must not cross filesystems
	f, err := os.CreateTemp(filepath.Dir(path), ".client.key.tmp-*")
	if err != nil {
		return nil, fmt.Errorf("config: create client key: %w", err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if _, err := f.WriteString(hex.EncodeToString(priv)); err != nil {
		f.Close()
		return nil, fmt.Errorf("config: write client key: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return nil, fmt.Errorf("config: sync client key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("config: write client key: %w", err)
	}
	if err := os.Link(tmp, path); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("config: create client key: %w", err)
	}
	return priv, nil
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
