package main

import (
	"os"
	"path/filepath"
)

func PathExists(d string) bool {
	_, err := os.Stat(d)
	if err != nil && os.IsNotExist(err) {
		return false
	}
	return true
}

func getTrustPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(configDir, "machine", "trust")
        return path, os.MkdirAll(path, 0755)
}
