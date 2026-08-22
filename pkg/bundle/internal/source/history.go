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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
)

const defaultHistoryLimit = 5

// certFingerprint decodes the first PEM block, parses it as an x509 certificate,
// and returns its SHA-256 fingerprint (hex-encoded) along with the parsed certificate.
func certFingerprint(pemData []byte) (string, *x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return "", nil, fmt.Errorf("failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), cert, nil
}

// sourceKey returns a stable, unique key for a source with keepCertHistory enabled.
func sourceKey(sourceType string, ref *trustapi.SourceObjectKeySelector) string {
	if ref == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s/%s", sourceType, ref.Name, ref.Key)
}

// updateHistory compares the current certificate against the last seen fingerprint
// and updates the history accordingly. On rotation, the previous certificate is
// moved into the entries list. Expired entries are pruned on every call.
func updateHistory(
	existing trustapi.SourceCertHistory,
	currentPEM []byte,
	limit int32,
	now time.Time,
) (trustapi.SourceCertHistory, error) {
	fingerprint, _, err := certFingerprint(currentPEM)
	if err != nil {
		return existing, err
	}

	// First reconcile or no rotation: just record the current cert.
	if existing.LastSeenFingerprint == "" || existing.LastSeenFingerprint == fingerprint {
		existing.LastSeenFingerprint = fingerprint
		existing.LastSeenPEM = string(currentPEM)
		existing.Entries = pruneExpired(existing.Entries, now)
		if len(existing.Entries) == 0 {
			existing.Entries = nil
		}
		return existing, nil
	}

	// Rotation detected: move the previous cert into entries.
	var updated trustapi.SourceCertHistory
	updated.LastSeenFingerprint = fingerprint
	updated.LastSeenPEM = string(currentPEM)

	entries := make([]trustapi.CertHistoryEntry, 0, len(existing.Entries)+1)

	if existing.LastSeenPEM != "" {
		_, oldCert, parseErr := certFingerprint([]byte(existing.LastSeenPEM))
		if parseErr != nil {
			// Log at call site; do not silently drop.
			return existing, fmt.Errorf("failed to parse previous certificate (fingerprint %s): %w", existing.LastSeenFingerprint, parseErr)
		}
		// Deduplicate: only add if this fingerprint is not already in entries.
		if !hasFingerprint(existing.Entries, existing.LastSeenFingerprint) {
			entries = append(entries, trustapi.CertHistoryEntry{
				PEM:         existing.LastSeenPEM,
				NotAfter:    metav1.NewTime(oldCert.NotAfter),
				AddedAt:     metav1.NewTime(now),
				Fingerprint: existing.LastSeenFingerprint,
			})
		}
	}
	entries = append(entries, existing.Entries...)

	entries = pruneExpired(entries, now)

	if len(entries) > int(limit) {
		entries = entries[:limit]
	}

	if len(entries) == 0 {
		entries = nil
	}
	updated.Entries = entries

	return updated, nil
}

// hasFingerprint returns true if any entry in the slice has the given fingerprint.
func hasFingerprint(entries []trustapi.CertHistoryEntry, fp string) bool {
	for _, e := range entries {
		if e.Fingerprint == fp {
			return true
		}
	}
	return false
}

// pruneExpired removes entries whose NotAfter is before now.
func pruneExpired(entries []trustapi.CertHistoryEntry, now time.Time) []trustapi.CertHistoryEntry {
	filtered := make([]trustapi.CertHistoryEntry, 0, len(entries))
	for _, e := range entries {
		if e.NotAfter.Time.After(now) {
			filtered = append(filtered, e)
		}
	}
	return filtered
}

// findHistoryByKey returns the SourceCertHistory for the given key, or a zero value if not found.
func findHistoryByKey(history []trustapi.SourceCertHistory, key string) trustapi.SourceCertHistory {
	for _, h := range history {
		if h.SourceKey == key {
			return h
		}
	}
	return trustapi.SourceCertHistory{}
}

// PruneOrphanedHistory removes history entries for sources that no longer
// have keepCertHistory enabled.
func PruneOrphanedHistory(
	history []trustapi.SourceCertHistory,
	sources []trustapi.BundleSource,
) []trustapi.SourceCertHistory {
	activeKeys := make(map[string]bool)
	for _, s := range sources {
		var st string
		var ref *trustapi.SourceObjectKeySelector
		switch {
		case s.Secret != nil:
			st, ref = "secret", s.Secret
		case s.ConfigMap != nil:
			st, ref = "configmap", s.ConfigMap
		default:
			continue
		}
		if ref.KeepCertHistory {
			activeKeys[sourceKey(st, ref)] = true
		}
	}

	var pruned []trustapi.SourceCertHistory
	for _, h := range history {
		if activeKeys[h.SourceKey] {
			pruned = append(pruned, h)
		}
	}
	return pruned
}
