package main

import (
	"errors"
	"testing"

	"nox-core/pkg/tun"
)

func TestCreateTUNWithRetryBusy(t *testing.T) {
	attempts := 0
	opener := func(string) (*tun.Tun, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("TUNSETIFF: device or resource busy")
		}
		return &tun.Tun{}, nil
	}
	cleaned := 0
	cleaner := func(string) {
		cleaned++
	}

	tdev, err := createTUNWithRetry("nox1", opener, cleaner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tdev == nil {
		t.Fatalf("expected tun device")
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
	if cleaned != 1 {
		t.Fatalf("expected cleaner to run once, got %d", cleaned)
	}
}

func TestCreateTUNWithRetryPassThrough(t *testing.T) {
	opener := func(string) (*tun.Tun, error) {
		return &tun.Tun{}, nil
	}
	cleaned := 0
	cleaner := func(string) {
		cleaned++
	}
	tdev, err := createTUNWithRetry("nox1", opener, cleaner)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tdev == nil {
		t.Fatalf("expected tun device")
	}
	if cleaned != 0 {
		t.Fatalf("cleaner should not run on success, got %d", cleaned)
	}
}

func TestIsDeviceBusy(t *testing.T) {
	if !isDeviceBusy(errors.New("device or resource busy")) {
		t.Fatalf("expected busy to be detected")
	}
	if isDeviceBusy(errors.New("other error")) {
		t.Fatalf("unexpected busy detection")
	}
	if isDeviceBusy(nil) {
		t.Fatalf("nil error should not be busy")
	}
}
