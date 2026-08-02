package factory

import "testing"

func TestUserPlaneBackendDefaults(t *testing.T) {
	cfg := &Config{Configuration: &Configuration{}}
	if got := cfg.GetUserPlaneBackend(); got != "linux" {
		t.Fatalf("backend=%q want linux", got)
	}
	if got := cfg.GetN3iwfDPControlSocket(); got != "/run/l25gc/n3iwf-dp.sock" {
		t.Fatalf("socket=%q", got)
	}
}

func TestUserPlaneBackendOverrides(t *testing.T) {
	cfg := &Config{Configuration: &Configuration{
		UserPlaneBackend:     "onvm",
		N3IWFDPControlSocket: "/tmp/test-n3iwf-dp.sock",
	}}
	if got := cfg.GetUserPlaneBackend(); got != "onvm" {
		t.Fatalf("backend=%q want onvm", got)
	}
	if got := cfg.GetN3iwfDPControlSocket(); got != "/tmp/test-n3iwf-dp.sock" {
		t.Fatalf("socket=%q", got)
	}
}
