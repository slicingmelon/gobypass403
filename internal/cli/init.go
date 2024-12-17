package cli

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/slicingmelon/go-bypass-403/internal/utils/logger"
)

//go:embed payloads/*
var defaultPayloads embed.FS

// GetToolDir returns the tool's data directory path
func GetToolDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("failed to get user config directory: %w", err)
	}
	return filepath.Join(configDir, "go-bypass-403"), nil
}

// GetPayloadsDir returns the payloads directory path
func GetPayloadsDir() (string, error) {
	toolDir, err := GetToolDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(toolDir, "payloads"), nil
}

// InitializePayloads copies default payloads to the tool directory
func InitializePayloads(forceUpdate bool) error {
	payloadsDir, err := GetPayloadsDir()
	if err != nil {
		return fmt.Errorf("failed to get payloads directory: %w", err)
	}

	// Create payloads directory if it doesn't exist
	if err := os.MkdirAll(payloadsDir, 0755); err != nil {
		return fmt.Errorf("failed to create payloads directory: %w", err)
	}

	// Read embedded payloads directory
	entries, err := defaultPayloads.ReadDir("payloads")
	if err != nil {
		return fmt.Errorf("failed to read embedded payloads: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		srcPath := filepath.Join("payloads", entry.Name())
		dstPath := filepath.Join(payloadsDir, entry.Name())

		// Skip if file exists and we're not forcing update
		if !forceUpdate {
			if _, err := os.Stat(dstPath); err == nil {
				logger.LogVerbose("Payload file already exists: %s", dstPath)
				continue
			}
		}

		// Copy payload file
		if err := copyPayloadFile(srcPath, dstPath); err != nil {
			return fmt.Errorf("failed to copy payload file %s: %w", entry.Name(), err)
		}
		logger.LogVerbose("Copied payload file: %s", dstPath)
	}

	return nil
}

func copyPayloadFile(src, dst string) error {
	data, err := defaultPayloads.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}
