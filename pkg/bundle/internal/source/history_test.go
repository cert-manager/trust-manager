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

package source

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/test/dummy"
)

func Test_certFingerprint(t *testing.T) {
	tests := map[string]struct {
		pem      string
		expError bool
	}{
		"valid PEM returns fingerprint and cert": {
			pem: dummy.TestCertificate1,
		},
		"invalid PEM returns error": {
			pem:      "not a certificate",
			expError: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			fp, cert, err := certFingerprint([]byte(tt.pem))

			if tt.expError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, fp)
			assert.NotNil(t, cert)
		})
	}
}

func Test_updateHistory(t *testing.T) {
	now := dummy.DummyInstant()

	fp1, cert1, err := certFingerprint([]byte(dummy.TestCertificate1))
	require.NoError(t, err)
	fp3, cert3, err := certFingerprint([]byte(dummy.TestCertificate3))
	require.NoError(t, err)
	fp4, _, err := certFingerprint([]byte(dummy.TestCertificate4))
	require.NoError(t, err)

	tests := map[string]struct {
		existing   trustapi.SourceCertHistory
		currentPEM string
		limit      int32
		expHistory trustapi.SourceCertHistory
		expError   bool
	}{
		"first reconcile with empty history sets lastSeen": {
			existing:   trustapi.SourceCertHistory{},
			currentPEM: dummy.TestCertificate1,
			limit:      5,
			expHistory: trustapi.SourceCertHistory{
				LastSeenFingerprint: fp1,
				LastSeenPEM:         dummy.TestCertificate1,
			},
		},
		"no rotation returns same history": {
			existing: trustapi.SourceCertHistory{
				LastSeenFingerprint: fp1,
				LastSeenPEM:         dummy.TestCertificate1,
			},
			currentPEM: dummy.TestCertificate1,
			limit:      5,
			expHistory: trustapi.SourceCertHistory{
				LastSeenFingerprint: fp1,
				LastSeenPEM:         dummy.TestCertificate1,
			},
		},
		"rotation detected moves old cert to entries": {
			existing: trustapi.SourceCertHistory{
				LastSeenFingerprint: fp1,
				LastSeenPEM:         dummy.TestCertificate1,
			},
			currentPEM: dummy.TestCertificate3,
			limit:      5,
			expHistory: trustapi.SourceCertHistory{
				LastSeenFingerprint: fp3,
				LastSeenPEM:         dummy.TestCertificate3,
				Entries: []trustapi.CertHistoryEntry{
					{
						PEM:         dummy.TestCertificate1,
						NotAfter:    metav1.NewTime(cert1.NotAfter),
						AddedAt:     metav1.NewTime(now),
						Fingerprint: fp1,
					},
				},
			},
		},
		"rotation preserves existing entries": {
			existing: trustapi.SourceCertHistory{
				LastSeenFingerprint: fp3,
				LastSeenPEM:         dummy.TestCertificate3,
				Entries: []trustapi.CertHistoryEntry{
					{
						PEM:         dummy.TestCertificate1,
						NotAfter:    metav1.NewTime(cert1.NotAfter),
						AddedAt:     metav1.NewTime(now.Add(-1 * time.Hour)),
						Fingerprint: fp1,
					},
				},
			},
			currentPEM: dummy.TestCertificate4,
			limit:      5,
			expHistory: trustapi.SourceCertHistory{
				LastSeenFingerprint: fp4,
				LastSeenPEM:         dummy.TestCertificate4,
				Entries: []trustapi.CertHistoryEntry{
					{
						PEM:         dummy.TestCertificate3,
						NotAfter:    metav1.NewTime(cert3.NotAfter),
						AddedAt:     metav1.NewTime(now),
						Fingerprint: fp3,
					},
					{
						PEM:         dummy.TestCertificate1,
						NotAfter:    metav1.NewTime(cert1.NotAfter),
						AddedAt:     metav1.NewTime(now.Add(-1 * time.Hour)),
						Fingerprint: fp1,
					},
				},
			},
		},
		"limit evicts oldest entries": {
			existing: trustapi.SourceCertHistory{
				LastSeenFingerprint: fp3,
				LastSeenPEM:         dummy.TestCertificate3,
				Entries: []trustapi.CertHistoryEntry{
					{
						PEM:         dummy.TestCertificate1,
						NotAfter:    metav1.NewTime(cert1.NotAfter),
						AddedAt:     metav1.NewTime(now.Add(-1 * time.Hour)),
						Fingerprint: fp1,
					},
				},
			},
			currentPEM: dummy.TestCertificate4,
			limit:      1,
			expHistory: trustapi.SourceCertHistory{
				LastSeenFingerprint: fp4,
				LastSeenPEM:         dummy.TestCertificate4,
				Entries: []trustapi.CertHistoryEntry{
					{
						PEM:         dummy.TestCertificate3,
						NotAfter:    metav1.NewTime(cert3.NotAfter),
						AddedAt:     metav1.NewTime(now),
						Fingerprint: fp3,
					},
				},
			},
		},
		"expired entries are pruned": {
			existing: trustapi.SourceCertHistory{
				LastSeenFingerprint: fp1,
				LastSeenPEM:         dummy.TestCertificate1,
				Entries: []trustapi.CertHistoryEntry{
					{
						PEM:         dummy.TestExpiredCertificate,
						NotAfter:    metav1.NewTime(now.Add(-24 * time.Hour)),
						AddedAt:     metav1.NewTime(now.Add(-48 * time.Hour)),
						Fingerprint: "expired-fp",
					},
				},
			},
			currentPEM: dummy.TestCertificate1,
			limit:      5,
			expHistory: trustapi.SourceCertHistory{
				LastSeenFingerprint: fp1,
				LastSeenPEM:         dummy.TestCertificate1,
			},
		},
		"invalid PEM returns error": {
			existing:   trustapi.SourceCertHistory{},
			currentPEM: "not a cert",
			limit:      5,
			expError:   true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result, err := updateHistory(tt.existing, []byte(tt.currentPEM), tt.limit, now)

			if tt.expError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expHistory, result)
		})
	}
}

func Test_PruneOrphanedHistory(t *testing.T) {
	tests := map[string]struct {
		history   []trustapi.SourceCertHistory
		sources   []trustapi.BundleSource
		expResult []trustapi.SourceCertHistory
	}{
		"active source retained": {
			history: []trustapi.SourceCertHistory{
				{SourceKey: "secret/my-ca/ca.crt", LastSeenFingerprint: "abc"},
			},
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "my-ca", Key: "ca.crt", KeepCertHistory: true}},
			},
			expResult: []trustapi.SourceCertHistory{
				{SourceKey: "secret/my-ca/ca.crt", LastSeenFingerprint: "abc"},
			},
		},
		"removed source pruned": {
			history: []trustapi.SourceCertHistory{
				{SourceKey: "secret/old-ca/ca.crt", LastSeenFingerprint: "abc"},
			},
			sources:   []trustapi.BundleSource{},
			expResult: nil,
		},
		"keepCertHistory toggled off prunes history": {
			history: []trustapi.SourceCertHistory{
				{SourceKey: "secret/my-ca/ca.crt", LastSeenFingerprint: "abc"},
			},
			sources: []trustapi.BundleSource{
				{Secret: &trustapi.SourceObjectKeySelector{Name: "my-ca", Key: "ca.crt", KeepCertHistory: false}},
			},
			expResult: nil,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expResult, PruneOrphanedHistory(tt.history, tt.sources))
		})
	}
}
