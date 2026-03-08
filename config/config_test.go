package config

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"dario.cat/mergo"
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.yaml.in/yaml/v3"
)

func TestConfig_Load(t *testing.T) {
	l := test.NewLogger()
	dir, err := os.MkdirTemp("", "config-test")
	// invalid yaml
	c := NewC(l)
	os.WriteFile(filepath.Join(dir, "01.yaml"), []byte(" invalid yaml"), 0644)
	require.EqualError(t, c.Load(dir), "yaml: unmarshal errors:\n  line 1: cannot unmarshal !!str `invalid...` into map[string]interface {}")

	// simple multi config merge
	c = NewC(l)
	os.RemoveAll(dir)
	os.Mkdir(dir, 0755)

	require.NoError(t, err)

	os.WriteFile(filepath.Join(dir, "01.yaml"), []byte("outer:\n  inner: hi"), 0644)
	os.WriteFile(filepath.Join(dir, "02.yml"), []byte("outer:\n  inner: override\nnew: hi"), 0644)
	require.NoError(t, c.Load(dir))
	expected := map[string]any{
		"outer": map[string]any{
			"inner": "override",
		},
		"new": "hi",
	}
	assert.Equal(t, expected, c.Settings)
}

func TestConfig_Get(t *testing.T) {
	l := test.NewLogger()
	// test simple type
	c := NewC(l)
	c.Settings["firewall"] = map[string]any{"outbound": "hi"}
	assert.Equal(t, "hi", c.Get("firewall.outbound"))

	// test complex type
	inner := []map[string]any{{"port": "1", "code": "2"}}
	c.Settings["firewall"] = map[string]any{"outbound": inner}
	assert.EqualValues(t, inner, c.Get("firewall.outbound"))

	// test missing
	assert.Nil(t, c.Get("firewall.nope"))
}

func TestConfig_GetStringSlice(t *testing.T) {
	l := test.NewLogger()
	c := NewC(l)
	c.Settings["slice"] = []any{"one", "two"}
	assert.Equal(t, []string{"one", "two"}, c.GetStringSlice("slice", []string{}))
}

func TestConfig_GetBool(t *testing.T) {
	l := test.NewLogger()
	c := NewC(l)
	c.Settings["bool"] = true
	assert.True(t, c.GetBool("bool", false))

	c.Settings["bool"] = "true"
	assert.True(t, c.GetBool("bool", false))

	c.Settings["bool"] = false
	assert.False(t, c.GetBool("bool", true))

	c.Settings["bool"] = "false"
	assert.False(t, c.GetBool("bool", true))

	c.Settings["bool"] = "Y"
	assert.True(t, c.GetBool("bool", false))

	c.Settings["bool"] = "yEs"
	assert.True(t, c.GetBool("bool", false))

	c.Settings["bool"] = "N"
	assert.False(t, c.GetBool("bool", true))

	c.Settings["bool"] = "nO"
	assert.False(t, c.GetBool("bool", true))
}

func TestConfig_HasChanged(t *testing.T) {
	l := test.NewLogger()
	// No reload has occurred, return false
	c := NewC(l)
	c.Settings["test"] = "hi"
	assert.False(t, c.HasChanged(""))

	// Test key change
	c = NewC(l)
	c.Settings["test"] = "hi"
	c.oldSettings = map[string]any{"test": "no"}
	assert.True(t, c.HasChanged("test"))
	assert.True(t, c.HasChanged(""))

	// No key change
	c = NewC(l)
	c.Settings["test"] = "hi"
	c.oldSettings = map[string]any{"test": "hi"}
	assert.False(t, c.HasChanged("test"))
	assert.False(t, c.HasChanged(""))
}

func TestConfig_ReloadConfig(t *testing.T) {
	l := test.NewLogger()
	done := make(chan bool, 1)
	dir, err := os.MkdirTemp("", "config-test")
	require.NoError(t, err)
	os.WriteFile(filepath.Join(dir, "01.yaml"), []byte("outer:\n  inner: hi"), 0644)

	c := NewC(l)
	require.NoError(t, c.Load(dir))

	assert.False(t, c.HasChanged("outer.inner"))
	assert.False(t, c.HasChanged("outer"))
	assert.False(t, c.HasChanged(""))

	os.WriteFile(filepath.Join(dir, "01.yaml"), []byte("outer:\n  inner: ho"), 0644)

	c.RegisterReloadCallback(func(c *C) {
		done <- true
	})

	c.ReloadConfig()
	assert.True(t, c.HasChanged("outer.inner"))
	assert.True(t, c.HasChanged("outer"))
	assert.True(t, c.HasChanged(""))

	// Make sure we call the callbacks
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		panic("timeout")
	}

}

// Ensure mergo merges are done the way we expect.
// This is needed to test for potential regressions, like:
// - https://github.com/imdario/mergo/issues/187
func TestConfig_MergoMerge(t *testing.T) {
	configs := [][]byte{
		[]byte(`
listen:
  port: 1234
`),
		[]byte(`
firewall:
  inbound:
    - port: 443
      proto: tcp
      groups:
        - server
    - port: 443
      proto: tcp
      groups:
        - webapp
`),
		[]byte(`
listen:
  host: 0.0.0.0
  port: 4242
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound:
    - port: any
      proto: icmp
      host: any
`),
	}

	var m map[string]any

	// merge the same way config.parse() merges
	for _, b := range configs {
		var nm map[string]any
		err := yaml.Unmarshal(b, &nm)
		require.NoError(t, err)

		// We need to use WithAppendSlice so that firewall rules in separate
		// files are appended together
		err = mergo.Merge(&nm, m, mergo.WithAppendSlice)
		m = nm
		require.NoError(t, err)
	}

	t.Logf("Merged Config: %#v", m)
	mYaml, err := yaml.Marshal(m)
	require.NoError(t, err)
	t.Logf("Merged Config as YAML:\n%s", mYaml)

	// If a bug is present, some items might be replaced instead of merged like we expect
	expected := map[string]any{
		"firewall": map[string]any{
			"inbound": []any{
				map[string]any{"host": "any", "port": "any", "proto": "icmp"},
				map[string]any{"groups": []any{"server"}, "port": 443, "proto": "tcp"},
				map[string]any{"groups": []any{"webapp"}, "port": 443, "proto": "tcp"}},
			"outbound": []any{
				map[string]any{"host": "any", "port": "any", "proto": "any"}}},
		"listen": map[string]any{
			"host": "0.0.0.0",
			"port": 4242,
		},
	}
	assert.Equal(t, expected, m)
}

func TestConfig_GetCertPaths(t *testing.T) {
	l := test.NewLogger()

	// File paths should be returned
	c := NewC(l)
	c.Settings["pki"] = map[string]any{
		"cert": "/etc/nebula/host.crt",
		"key":  "/etc/nebula/host.key",
		"ca":   "/etc/nebula/ca.crt",
	}
	paths := c.GetCertPaths()
	assert.Len(t, paths, 3)
	assert.Contains(t, paths, "/etc/nebula/host.crt")
	assert.Contains(t, paths, "/etc/nebula/host.key")
	assert.Contains(t, paths, "/etc/nebula/ca.crt")

	// Inline PEM data should be skipped
	c = NewC(l)
	c.Settings["pki"] = map[string]any{
		"cert": "-----BEGIN NEBULA CERTIFICATE-----\ndata\n-----END NEBULA CERTIFICATE-----",
		"key":  "/etc/nebula/host.key",
		"ca":   "-----BEGIN NEBULA CERTIFICATE-----\ndata\n-----END NEBULA CERTIFICATE-----",
	}
	paths = c.GetCertPaths()
	assert.Len(t, paths, 1)
	assert.Equal(t, "/etc/nebula/host.key", paths[0])

	// PKCS#11 URIs should be skipped
	c = NewC(l)
	c.Settings["pki"] = map[string]any{
		"cert": "/etc/nebula/host.crt",
		"key":  "pkcs11:token=mytoken",
		"ca":   "/etc/nebula/ca.crt",
	}
	paths = c.GetCertPaths()
	assert.Len(t, paths, 2)
	assert.Contains(t, paths, "/etc/nebula/host.crt")
	assert.Contains(t, paths, "/etc/nebula/ca.crt")

	// Empty or missing settings should return empty
	c = NewC(l)
	paths = c.GetCertPaths()
	assert.Empty(t, paths)
}

func TestConfig_CatchCertChange(t *testing.T) {
	l := test.NewLogger()

	// Set up a temp directory with config and cert files
	configDir, err := os.MkdirTemp("", "config-certwatch-test")
	require.NoError(t, err)
	defer os.RemoveAll(configDir)

	certDir, err := os.MkdirTemp("", "certs-certwatch-test")
	require.NoError(t, err)
	defer os.RemoveAll(certDir)

	certPath := filepath.Join(certDir, "host.crt")
	keyPath := filepath.Join(certDir, "host.key")
	caPath := filepath.Join(certDir, "ca.crt")

	require.NoError(t, os.WriteFile(certPath, []byte("cert-data"), 0644))
	require.NoError(t, os.WriteFile(keyPath, []byte("key-data"), 0644))
	require.NoError(t, os.WriteFile(caPath, []byte("ca-data"), 0644))

	// Create config that references those cert paths
	configYaml := "pki:\n  cert: " + certPath + "\n  key: " + keyPath + "\n  ca: " + caPath + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configYaml), 0644))

	c := NewC(l)
	require.NoError(t, c.Load(configDir))

	// Track reload calls via callback
	var reloadCount atomic.Int32
	c.RegisterReloadCallback(func(c *C) {
		reloadCount.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start watching with a short debounce for testing
	c.CatchCertChange(ctx, 100*time.Millisecond)

	// Give the watcher time to start
	time.Sleep(50 * time.Millisecond)

	// Modify a cert file
	require.NoError(t, os.WriteFile(certPath, []byte("cert-data-updated"), 0644))

	// Wait for debounce + processing
	time.Sleep(500 * time.Millisecond)

	assert.GreaterOrEqual(t, reloadCount.Load(), int32(1), "ReloadConfig should have been called at least once")

	// Reset count and test debouncing: rapid writes should coalesce into one reload
	startCount := reloadCount.Load()
	require.NoError(t, os.WriteFile(certPath, []byte("cert-v2"), 0644))
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, os.WriteFile(keyPath, []byte("key-v2"), 0644))
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, os.WriteFile(caPath, []byte("ca-v2"), 0644))

	// Wait for debounce to fire
	time.Sleep(500 * time.Millisecond)

	endCount := reloadCount.Load()
	// The debounced rapid writes should result in at most 2 reload calls
	// (ideally 1, but filesystem event timing can vary)
	assert.LessOrEqual(t, endCount-startCount, int32(2),
		"Debouncing should coalesce rapid writes into few reloads")
	assert.GreaterOrEqual(t, endCount-startCount, int32(1),
		"At least one reload should occur for the rapid writes")
}

func TestConfig_CatchCertChange_ContextCancel(t *testing.T) {
	l := test.NewLogger()

	certDir, err := os.MkdirTemp("", "certs-cancel-test")
	require.NoError(t, err)
	defer os.RemoveAll(certDir)

	certPath := filepath.Join(certDir, "host.crt")
	require.NoError(t, os.WriteFile(certPath, []byte("cert-data"), 0644))

	configDir, err := os.MkdirTemp("", "config-cancel-test")
	require.NoError(t, err)
	defer os.RemoveAll(configDir)

	configYaml := "pki:\n  cert: " + certPath + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configYaml), 0644))

	c := NewC(l)
	require.NoError(t, c.Load(configDir))

	var reloadCount atomic.Int32
	c.RegisterReloadCallback(func(c *C) {
		reloadCount.Add(1)
	})

	ctx, cancel := context.WithCancel(context.Background())
	c.CatchCertChange(ctx, 100*time.Millisecond)
	time.Sleep(50 * time.Millisecond)

	// Cancel the context to stop the watcher
	cancel()
	time.Sleep(50 * time.Millisecond)

	// Write to cert file after cancellation — should NOT trigger reload
	beforeCount := reloadCount.Load()
	require.NoError(t, os.WriteFile(certPath, []byte("cert-after-cancel"), 0644))
	time.Sleep(300 * time.Millisecond)

	assert.Equal(t, beforeCount, reloadCount.Load(),
		"No reload should occur after context cancellation")
}

func TestConfig_CatchCertChange_NoPath(t *testing.T) {
	l := test.NewLogger()
	c := NewC(l)

	// No path set — CatchCertChange should return immediately without panic
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.CatchCertChange(ctx, 100*time.Millisecond)
}

func TestConfig_CatchCertChange_InlinePEM(t *testing.T) {
	l := test.NewLogger()

	configDir, err := os.MkdirTemp("", "config-inline-test")
	require.NoError(t, err)
	defer os.RemoveAll(configDir)

	// All inline PEM — no files to watch
	configYaml := `pki:
  cert: "-----BEGIN NEBULA CERTIFICATE-----\ndata\n-----END NEBULA CERTIFICATE-----"
  key: "-----BEGIN NEBULA X25519 PRIVATE KEY-----\ndata\n-----END NEBULA X25519 PRIVATE KEY-----"
  ca: "-----BEGIN NEBULA CERTIFICATE-----\ndata\n-----END NEBULA CERTIFICATE-----"
`
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "config.yaml"), []byte(configYaml), 0644))

	c := NewC(l)
	require.NoError(t, c.Load(configDir))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Should not panic or error — just logs a warning and returns
	c.CatchCertChange(ctx, 100*time.Millisecond)
}
