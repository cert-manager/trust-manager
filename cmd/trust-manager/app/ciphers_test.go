/*
Copyright 2025 The cert-manager Authors.

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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	cliflag "k8s.io/component-base/cli/flag"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/cert-manager/trust-manager/cmd/trust-manager/app/options"
)

func TestCiphersSuite(t *testing.T) {
	tmpDir := t.TempDir()
	err := setupWebHookServer(tmpDir)
	if err != nil {
		t.Fatal(fmt.Errorf("unable to setup webhook server %s\n", err))
	}

	t.Run("TLS 1.2 client connect to TLS 1.2 server, ciphers suite supported", func(t *testing.T) {
		client := http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2: false,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint: gosec
					MinVersion:         tls.VersionTLS12,
					MaxVersion:         tls.VersionTLS12,
					CipherSuites: []uint16{
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
					},
				},
			},
		}

		resp, err := client.Get(fmt.Sprintf("https://%s", net.JoinHostPort("localhost", "6443"))) //nolint: noctx

		if resp != nil {
			defer resp.Body.Close()
		}

		if err != nil {
			t.Fatalf("error to connect to webhook server, %s\n", err)
		}
	})

	t.Run("TLS 1.2 client connect to TLS 1.2 server, ciphers suite unsupported", func(t *testing.T) {
		client := http.Client{
			Transport: &http.Transport{
				ForceAttemptHTTP2: false,
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint: gosec
					MinVersion:         tls.VersionTLS12,
					MaxVersion:         tls.VersionTLS12,
					CipherSuites: []uint16{
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
					},
				},
			},
		}

		resp, err := client.Get(fmt.Sprintf("https://%s", net.JoinHostPort("localhost", "6443"))) //nolint: noctx

		if resp != nil {
			defer resp.Body.Close()
		}

		if err == nil {
			t.Error("expected an error from talking to a server with an unsupported cipher suite but got none")
			return
		}
	})
}

func setupWebHookServer(tmpDir string) error {
	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("unable to get local hostname %s\n", err)
	}

	err = genPrivAndCert(tmpDir)
	if err != nil {
		return fmt.Errorf("unable to generate certificate and privkey %s\n", err)
	}

	args := []string{
		"--readiness-probe-port=9443",
		"--readiness-probe-path=/readyz",
		"--leader-election-lease-duration=15s",
		"--leader-election-renew-deadline=10s",
		"--metrics-port=9402",
		"--trust-namespace=cert-manager",
		"--secret-targets-enabled=false",
		"--filter-expired-certificates=false",
		"--webhook-host=" + hostname,
		"--webhook-port=6443",
		"--tls-min-version=VersionTLS12",
		"--tls-cipher-suites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_128_GCM_SHA256",
	}

	opts := options.New()

	cmd := &cobra.Command{
		RunE: func(cmd *cobra.Command, args []string) error {
			srv := webhook.NewServer(webhook.Options{
				CertDir: tmpDir,
				Port:    opts.Port,

				TLSOpts: []func(*tls.Config){
					func(cfg *tls.Config) {
						cfg.MinVersion, err = cliflag.TLSVersion(opts.MinTLSVersion)
						if err != nil {
							cmd.PrintErrf("error parsing minimum TLS version, given %s\n", opts.MinTLSVersion)
						}

						cfg.CipherSuites, err = cliflag.TLSCipherSuites(opts.CipherSuite)
						if err != nil {
							cmd.PrintErrf("error parsing cipher suites, given %s\n", opts.CipherSuite)
						}
					},
				},
			})

			if err != nil {
				cmd.PrintErrf("error creating webhook server %s\n", err)
				return err
			}

			go func() {
				if err := srv.Start(cmd.Context()); err != nil {
					cmd.PrintErrf("error starting webhook server %s\n", err)
				}
			}()

			return nil
		},
	}
	cmd.SetArgs(args)
	opts.Prepare(cmd)
	err = cmd.Execute()
	if err != nil {
		cmd.PrintErrf("error: %v\n", err)
		return err
	}
	return nil
}

// This implementation was taken as is from
// https://go.dev/src/crypto/tls/generate_cert.go source file
func genPrivAndCert(dir string) error {
	var priv any
	var err error
	priv, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("Failed to generate private key: %v", err)
	}

	keyUsage := x509.KeyUsageDigitalSignature
	if _, isRSA := priv.(*rsa.PrivateKey); isRSA {
		keyUsage |= x509.KeyUsageKeyEncipherment
	}

	var notBefore = time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	hosts := strings.Split("localhost, 127.0.0.1", ",")
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %v", err)
	}

	certOut, err := os.Create(path.Join(dir, "tls.crt"))
	if err != nil {
		return fmt.Errorf("Failed to open cert.pem for writing: %v", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("Failed to write data to tls.crt: %v", err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("Error closing tls.crt: %v", err)
	}
	log.Print("wrote tls.crt\n")

	keyOut, err := os.OpenFile(path.Join(dir, "tls.key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("Failed to open tls.key for writing: %v", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return fmt.Errorf("Failed to write data to tls.key: %v", err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("Error closing tls.key: %v", err)
	}
	log.Print("wrote tls.key\n")
	return nil
}

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}
