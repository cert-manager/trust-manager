/*
Copyright 2026 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package app

import (
	"crypto/tls"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cert-manager/trust-manager/cmd/trust-manager/app/options"
)

func TestGetTLSOptions(t *testing.T) {
	tests := map[string]struct {
		config      options.TLSConfig
		wantMin     uint16
		wantCiphers []uint16
		wantCurves  []tls.CurveID
		wantErr     bool
	}{
		"empty config leaves tls.Config defaults unset": {
			config: options.TLSConfig{},
		},
		"curve preferences are applied as crypto/tls CurveIDs": {
			config: options.TLSConfig{
				CurvePreferences: []int32{int32(tls.X25519), int32(tls.CurveP256)},
			},
			wantCurves: []tls.CurveID{tls.X25519, tls.CurveP256},
		},
		"curve preferences combine with min version and cipher suites": {
			config: options.TLSConfig{
				MinVersion:       "VersionTLS12",
				CipherSuites:     []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
				CurvePreferences: []int32{int32(tls.X25519)},
			},
			wantMin:     tls.VersionTLS12,
			wantCiphers: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
			wantCurves:  []tls.CurveID{tls.X25519},
		},
		"unknown curve ID is rejected": {
			config: options.TLSConfig{
				CurvePreferences: []int32{9999},
			},
			wantErr: true,
		},
		"duplicate curve ID is rejected": {
			config: options.TLSConfig{
				CurvePreferences: []int32{int32(tls.X25519), int32(tls.X25519)},
			},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			opts, err := GetTLSOptions(tc.config)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			cfg := &tls.Config{}
			for _, opt := range opts {
				opt(cfg)
			}

			assert.Equal(t, tc.wantMin, cfg.MinVersion)
			assert.Equal(t, tc.wantCiphers, cfg.CipherSuites)
			assert.Equal(t, tc.wantCurves, cfg.CurvePreferences)
		})
	}
}

// Helm passes a single comma-separated flag value (same shape as kube-apiserver).
func TestTLSCurvePreferencesFlag(t *testing.T) {
	opts := options.New()
	cmd := &cobra.Command{Use: "trust-manager"}
	opts.Prepare(cmd)

	// 23=P-256, 29=X25519; Helm passes this same comma-separated form.
	require.NoError(t, cmd.ParseFlags([]string{"--tls-curve-preferences=23,29"}))
	assert.Equal(t, []int32{int32(tls.CurveP256), int32(tls.X25519)}, opts.TLSConfig.CurvePreferences)

	tlsOpts, err := GetTLSOptions(opts.TLSConfig)
	require.NoError(t, err)

	cfg := &tls.Config{}
	for _, opt := range tlsOpts {
		opt(cfg)
	}
	assert.Equal(t, []tls.CurveID{tls.CurveP256, tls.X25519}, cfg.CurvePreferences)
}
