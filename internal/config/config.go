// Package config provides configuration loading for Hunter.
// It supports a layered configuration approach with priority:
// CLI flags > environment variables (HUNTER_*) > config file (~/.hunter.yaml).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ScanProfile defines a named set of scanners to run together.
type ScanProfile struct {
	Name     string   `mapstructure:"name" yaml:"name"`
	Scanners []string `mapstructure:"scanners" yaml:"scanners"`
}

// Config holds all Hunter configuration options.
type Config struct {
	DefaultTarget string        `mapstructure:"default_target" yaml:"default_target"`
	OutputFormat  string        `mapstructure:"output_format" yaml:"output_format"`
	Concurrency   int           `mapstructure:"concurrency" yaml:"concurrency"`
	Timeout       time.Duration `mapstructure:"timeout" yaml:"timeout"`
	WordlistPath  string        `mapstructure:"wordlist_path" yaml:"wordlist_path"`
	ScanProfiles  []ScanProfile `mapstructure:"scan_profiles" yaml:"scan_profiles"`
}

// Defaults returns a Config populated with default values.
func Defaults() Config {
	return Config{
		OutputFormat: "table",
		Concurrency:  10,
		Timeout:      5 * time.Second,
	}
}

// Load reads configuration from ~/.hunter.yaml and environment variables.
// It does NOT apply CLI flag overrides — call ApplyFlags for that.
func Load() (*Config, error) {
	v := viper.New()
	setDefaults(v)

	v.SetConfigName(".hunter")
	v.SetConfigType("yaml")

	home, err := os.UserHomeDir()
	if err == nil {
		v.AddConfigPath(home)
	}

	v.SetEnvPrefix("HUNTER")
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config file: %w", err)
		}
	}

	cfg := Defaults()
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return &cfg, nil
}

// LoadFromFile reads configuration from a specific file path.
func LoadFromFile(path string) (*Config, error) {
	v := viper.New()
	setDefaults(v)

	v.SetConfigFile(path)

	v.SetEnvPrefix("HUNTER")
	v.AutomaticEnv()

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := Defaults()
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return &cfg, nil
}

// ApplyFlags overrides config values with any CLI flags that were explicitly set.
func ApplyFlags(cfg *Config, cmd *cobra.Command) {
	flags := cmd.Flags()

	if flags.Changed("target") {
		val, _ := flags.GetString("target")
		cfg.DefaultTarget = val
	}
	if flags.Changed("output") {
		val, _ := flags.GetString("output")
		cfg.OutputFormat = val
	}
	if flags.Changed("concurrency") {
		val, _ := flags.GetInt("concurrency")
		cfg.Concurrency = val
	}
	if flags.Changed("timeout") {
		val, _ := flags.GetDuration("timeout")
		cfg.Timeout = val
	}
}

// GetProfile returns the scan profile with the given name, or nil if not found.
func (c *Config) GetProfile(name string) *ScanProfile {
	for i := range c.ScanProfiles {
		if c.ScanProfiles[i].Name == name {
			return &c.ScanProfiles[i]
		}
	}
	return nil
}

// ConfigFilePath returns the default config file path (~/.hunter.yaml).
func ConfigFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".hunter.yaml"
	}
	return filepath.Join(home, ".hunter.yaml")
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("output_format", "table")
	v.SetDefault("concurrency", 10)
	v.SetDefault("timeout", 5*time.Second)
}
