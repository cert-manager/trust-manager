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

package truststore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path"
	"testing"
	"time"

	"github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/util"
	"github.com/cert-manager/trust-manager/test/dummy"
)

func Test_Java_keytool_can_read_JKS(t *testing.T) {
	keytool, err := exec.LookPath("keytool")
	if err != nil {
		t.Skip("these tests require installation of Java to run")
	}

	bundle := dummy.JoinCerts(dummy.TestCertificate1, dummy.TestCertificate2, dummy.TestCertificate3)

	certPool := util.NewCertPool()
	if err := certPool.AddCertsFromPEM([]byte(bundle)); err != nil {
		t.Fatal(err)
	}

	encoder := NewJKSEncoder(v1alpha1.DefaultJKSPassword)
	store, err := encoder.Encode(certPool)
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(path.Join(t.TempDir(), "cacerts"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, err = f.Write(store)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(
		t.Context(),
		keytool,
		"-list", "-keystore", f.Name(), "-storepass", v1alpha1.DefaultJKSPassword,
	) // #nosec G204,G702 -- keytool path and keystore are trusted in test environment
	out, err := cmd.CombinedOutput()
	t.Logf("combined out:\n%s", string(out))
	if err != nil {
		t.Fatalf("cmd.Run() failed with %s", err)
	}
}

func Test_Java_can_use_JKS(t *testing.T) {
	javac, err := exec.LookPath("javac")
	if err != nil {
		t.Skip("these tests require installation of Java to run")
	}

	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Now()
	template := &x509.Certificate{
		BasicConstraintsValid: true,
		SerialNumber:          big.NewInt(1658),
		PublicKeyAlgorithm:    x509.ECDSA,
		PublicKey:             pk.Public(),
		IsCA:                  true,
		Subject: pkix.Name{
			CommonName: "localhost",
		},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   notBefore,
		NotAfter:    notBefore.Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, pk.Public(), pk)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{cert.Raw},
			Leaf:        cert,
			PrivateKey:  pk,
		}},
		MinVersion: tls.VersionTLS12,
	}
	server.StartTLS()
	defer server.Close()

	workDir := t.TempDir()

	cmd := exec.CommandContext(t.Context(), javac,
		"-d", workDir,
		"-Xlint:-options", "-source", "8", "-target", "8",
		"TestHTTPConnection.java") // #nosec G204
	out, err := cmd.CombinedOutput()
	t.Logf("combined out:\n%s", string(out))
	if err != nil {
		t.Fatalf("cmd.Run() failed with %s", err)
	}

	certPool := util.NewCertPool()
	certPool.AddCert(cert)
	encoder := NewJKSEncoder(v1alpha1.DefaultJKSPassword)
	store, err := encoder.Encode(certPool)
	if err != nil {
		t.Fatal(err)
	}

	jksPath := path.Join(workDir, "cacerts")
	f, err := os.Create(jksPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	_, err = f.Write(store)
	if err != nil {
		t.Fatal(err)
	}

	javaDir, _ := path.Split(javac)
	cmd = exec.CommandContext(t.Context(), path.Join(javaDir, "java"),
		"-cp", workDir,
		"-Djavax.net.ssl.trustStoreType=JKS",
		"-Djavax.net.ssl.trustStore="+jksPath,
		"-Djavax.net.ssl.trustStorePassword="+v1alpha1.DefaultJKSPassword,
		"TestHTTPConnection", server.URL) // #nosec G204
	out, err = cmd.CombinedOutput()
	t.Logf("combined out:\n%s", string(out))
	if err != nil {
		t.Fatalf("cmd.Run() failed with %s", err)
	}
}
