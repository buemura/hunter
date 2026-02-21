package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaults(t *testing.T) {
	cfg := Defaults()

	assert.Equal(t, "", cfg.DefaultTarget)
	assert.Equal(t, "table", cfg.OutputFormat)
	assert.Equal(t, 10, cfg.Concurrency)
	assert.Equal(t, 5*time.Second, cfg.Timeout)
	assert.Equal(t, "", cfg.WordlistPath)
	assert.Empty(t, cfg.ScanProfiles)
}

func TestLoad_NoConfigFile(t *testing.T) {
	// Ensure no env vars interfere.
	for _, key := range []string{"HUNTER_DEFAULT_TARGET", "HUNTER_OUTPUT_FORMAT", "HUNTER_CONCURRENCY", "HUNTER_TIMEOUT", "HUNTER_WORDLIST_PATH"} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "table", cfg.OutputFormat)
	assert.Equal(t, 10, cfg.Concurrency)
	assert.Equal(t, 5*time.Second, cfg.Timeout)
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, ".hunter.yaml")

	content := `default_target: "https://example.com"
output_format: "json"
concurrency: 20
timeout: 10s
wordlist_path: "/tmp/wordlist.txt"
scan_profiles:
  - name: quick
    scanners:
      - port
      - headers
  - name: full
    scanners:
      - port
      - headers
      - ssl
      - dirs
      - vuln
`
	err := os.WriteFile(cfgFile, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := LoadFromFile(cfgFile)
	require.NoError(t, err)

	assert.Equal(t, "https://example.com", cfg.DefaultTarget)
	assert.Equal(t, "json", cfg.OutputFormat)
	assert.Equal(t, 20, cfg.Concurrency)
	assert.Equal(t, 10*time.Second, cfg.Timeout)
	assert.Equal(t, "/tmp/wordlist.txt", cfg.WordlistPath)

	require.Len(t, cfg.ScanProfiles, 2)
	assert.Equal(t, "quick", cfg.ScanProfiles[0].Name)
	assert.Equal(t, []string{"port", "headers"}, cfg.ScanProfiles[0].Scanners)
	assert.Equal(t, "full", cfg.ScanProfiles[1].Name)
	assert.Equal(t, []string{"port", "headers", "ssl", "dirs", "vuln"}, cfg.ScanProfiles[1].Scanners)
}

func TestLoadFromFile_NotFound(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/.hunter.yaml")
	assert.Error(t, err)
}

func TestLoadFromFile_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, ".hunter.yaml")

	err := os.WriteFile(cfgFile, []byte("{{invalid yaml"), 0644)
	require.NoError(t, err)

	_, err = LoadFromFile(cfgFile)
	assert.Error(t, err)
}

func TestLoad_EnvVarOverrides(t *testing.T) {
	t.Setenv("HUNTER_CONCURRENCY", "50")
	t.Setenv("HUNTER_OUTPUT_FORMAT", "json")

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, 50, cfg.Concurrency)
	assert.Equal(t, "json", cfg.OutputFormat)
}

func TestApplyFlags(t *testing.T) {
	cfg := Defaults()

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("target", "", "")
	cmd.Flags().String("output", "table", "")
	cmd.Flags().Int("concurrency", 10, "")
	cmd.Flags().Duration("timeout", 5*time.Second, "")

	// Simulate setting flags via command line.
	err := cmd.Flags().Set("target", "https://test.com")
	require.NoError(t, err)
	err = cmd.Flags().Set("concurrency", "25")
	require.NoError(t, err)

	ApplyFlags(&cfg, cmd)

	assert.Equal(t, "https://test.com", cfg.DefaultTarget)
	assert.Equal(t, "table", cfg.OutputFormat) // Not changed — flag wasn't set.
	assert.Equal(t, 25, cfg.Concurrency)
	assert.Equal(t, 5*time.Second, cfg.Timeout) // Not changed — flag wasn't set.
}

func TestApplyFlags_NoOverrideWhenUnchanged(t *testing.T) {
	cfg := Config{
		DefaultTarget: "https://original.com",
		OutputFormat:  "json",
		Concurrency:   30,
		Timeout:       15 * time.Second,
	}

	cmd := &cobra.Command{Use: "test"}
	cmd.Flags().String("target", "", "")
	cmd.Flags().String("output", "table", "")
	cmd.Flags().Int("concurrency", 10, "")
	cmd.Flags().Duration("timeout", 5*time.Second, "")

	// Don't set any flags — none should override.
	ApplyFlags(&cfg, cmd)

	assert.Equal(t, "https://original.com", cfg.DefaultTarget)
	assert.Equal(t, "json", cfg.OutputFormat)
	assert.Equal(t, 30, cfg.Concurrency)
	assert.Equal(t, 15*time.Second, cfg.Timeout)
}

func TestGetProfile(t *testing.T) {
	cfg := &Config{
		ScanProfiles: []ScanProfile{
			{Name: "quick", Scanners: []string{"port", "headers"}},
			{Name: "full", Scanners: []string{"port", "headers", "ssl", "dirs", "vuln"}},
		},
	}

	t.Run("found", func(t *testing.T) {
		p := cfg.GetProfile("quick")
		require.NotNil(t, p)
		assert.Equal(t, "quick", p.Name)
		assert.Equal(t, []string{"port", "headers"}, p.Scanners)
	})

	t.Run("not found", func(t *testing.T) {
		p := cfg.GetProfile("nonexistent")
		assert.Nil(t, p)
	})
}

func TestConfigFilePath(t *testing.T) {
	path := ConfigFilePath()
	assert.Contains(t, path, ".hunter.yaml")
}

func TestLoadFromFile_PartialConfig(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, ".hunter.yaml")

	content := `concurrency: 50
`
	err := os.WriteFile(cfgFile, []byte(content), 0644)
	require.NoError(t, err)

	cfg, err := LoadFromFile(cfgFile)
	require.NoError(t, err)

	// Explicitly set values.
	assert.Equal(t, 50, cfg.Concurrency)
	// Defaults for unset values.
	assert.Equal(t, "table", cfg.OutputFormat)
	assert.Equal(t, 5*time.Second, cfg.Timeout)
}
