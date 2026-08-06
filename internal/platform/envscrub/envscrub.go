// Package envscrub is the single definition of which environment variables never reach a subprocess.
package envscrub

import (
	"os"
	"strings"
)

// keys whose VALUE is a credential wherever they appear
var secretPrefixes = []string{
	"QUARRY_",
	"OPENAI_",
	"ANTHROPIC_",
	"ZAI_",
	"GEMINI_",
	"AWS_",
	"AZURE_",
	"GOOGLE_",
	"FLY_",
}

var secretSubstrings = []string{
	"API_KEY",
	"APIKEY",
	"SECRET",
	"TOKEN",
	"PASSWORD",
	"PASSWD",
	"CREDENTIAL",
}

// Environ is os.Environ() with every secret-bearing variable removed.
func Environ() []string {
	src := os.Environ()
	out := make([]string, 0, len(src))
	for _, e := range src {
		key, _, _ := strings.Cut(e, "=")
		if IsSecretKey(key) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// IsSecretKey fails closed: a key that merely looks credential-bearing is scrubbed.
func IsSecretKey(key string) bool {
	up := strings.ToUpper(key)
	for _, prefix := range secretPrefixes {
		if strings.HasPrefix(up, prefix) {
			return true
		}
	}
	for _, sub := range secretSubstrings {
		if strings.Contains(up, sub) {
			return true
		}
	}
	return false
}
