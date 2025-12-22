package main

import (
	"strings"

	"nox-core/pkg/tun"
)

// createTUNWithRetry tries to create TUN, and on "device busy" cleans up once and retries.
func createTUNWithRetry(name string, opener func(string) (*tun.Tun, error), cleaner func(string)) (*tun.Tun, error) {
	t, err := opener(name)
	if err == nil {
		return t, nil
	}
	if !isDeviceBusy(err) {
		return nil, err
	}
	if cleaner != nil {
		cleaner(name)
	}
	t, err = opener(name)
	if err != nil {
		return nil, err
	}
	return t, nil
}

func isDeviceBusy(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "device or resource busy")
}
