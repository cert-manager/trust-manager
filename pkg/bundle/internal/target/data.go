/*
Copyright 2021 The cert-manager Authors.

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

package target

import (
	"fmt"

	trustapi "github.com/cert-manager/trust-manager/pkg/apis/trust/v1alpha1"
	"github.com/cert-manager/trust-manager/pkg/bundle/internal/truststore"
	"github.com/cert-manager/trust-manager/pkg/util"
)

// Data contains the resulting PEM-encoded certificate data from concatenating all the bundle sources together
// and binary data for any additional formats.
type Data struct {
	Data       string
	BinaryData map[string][]byte
}

func (b *Data) Populate(pool *util.CertPool, formats *trustapi.AdditionalFormats) error {
	b.Data = pool.PEM()

	if formats != nil {
		b.BinaryData = make(map[string][]byte)

		if formats.JKS != nil {
			encoded, err := truststore.NewJKSEncoder(*formats.JKS.Password).Encode(pool)
			if err != nil {
				return fmt.Errorf("failed to encode JKS: %w", err)
			}
			b.BinaryData[formats.JKS.Key] = encoded
		}

		if formats.PKCS12 != nil {
			encoded, err := truststore.NewPKCS12Encoder(*formats.PKCS12.Password).Encode(pool)
			if err != nil {
				return fmt.Errorf("failed to encode PKCS12: %w", err)
			}
			b.BinaryData[formats.PKCS12.Key] = encoded
		}
	}
	return nil
}
