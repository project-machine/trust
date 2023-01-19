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

func getSudiDir() (string, error) {
	dataDir, err := UserDataDir()
	if err != nil {
		return "", err
	}
	sudiPath := filepath.Join(dataDir, "machine", "trust")
	return sudiPath, os.MkdirAll(sudiPath, 0755)
}

func UserDataDir() (string, error) {
	p, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(p, ".local", "share"), nil
}

func ConfPath(cluster string) string {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(configDir, "machine", cluster, "machine.yaml")
}

// Get the location where keysets are stored
func getMosKeyPath() (string, error) {
	dataDir, err := UserDataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "machine", "trust", "keys"), nil
}
