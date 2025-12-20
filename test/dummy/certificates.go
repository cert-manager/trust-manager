/*
Copyright 2023 The cert-manager Authors.

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

// Contains various PEM-encoded certificates for use in other tests.

package dummy

import (
	"strings"
	"time"
)

// DummyInstant returns a time at which all dummy certs should be unexpired except
// for any which are specifically created to have expired.
func DummyInstant() time.Time {
	return time.Date(2024, time.January, 17, 16, 56, 07, 0, time.UTC)
}

const (
	// NB: TestCertificate1 is expected to have the following properties:
	// 1. Same Subject as TestCertificate2
	// 2. Self signed (issuer == subject)
	// There are tests to assert these properties.
	// Certificate:
	//     Data:
	//         Version: 3 (0x2)
	//         Serial Number:
	//             0f:7a:09:a8:71:09:02:34:f6:e6:b1:06:63:a9:0b:81
	//         Signature Algorithm: ecdsa-with-SHA256
	//         Issuer: O = cert-manager, CN = cmct-test-root
	//         Validity
	//             Not Before: Nov 25 13:03:54 2022 GMT
	//             Not After : Nov 22 13:03:54 2032 GMT
	//         Subject: O = cert-manager, CN = cmct-test-root
	//         Subject Public Key Info:
	//             Public Key Algorithm: id-ecPublicKey
	//                 Public-Key: (256 bit)
	//                 pub:
	//                     04:6d:1a:c4:54:86:d9:31:3e:23:60:4f:da:fc:1d:
	//                     5d:ce:fd:a1:40:93:51:ec:2c:75:d8:19:3a:ad:9f:
	//                     f9:d2:a3:59:4e:57:c8:f3:5c:10:0c:4c:a7:7e:ed:
	//                     56:34:2f:b0:2e:1c:45:81:28:fa:e6:12:98:c5:5c:
	//                     42:2e:24:91:51
	//                 ASN1 OID: prime256v1
	//                 NIST CURVE: P-256
	//         X509v3 extensions:
	//             X509v3 Basic Constraints: critical
	//                 CA:TRUE, pathlen:3
	//             X509v3 Subject Key Identifier:
	//                 D7:04:1B:6B:B3:CD:3F:5B:73:32:D2:9C:FB:84:7B:DF:27:26:45:50
	//     Signature Algorithm: ecdsa-with-SHA256
	//          30:45:02:21:00:9e:37:6f:d9:ee:34:89:24:ae:e6:ee:47:19:
	//          fd:48:09:22:a6:f3:29:2d:64:b7:27:14:43:9d:3e:76:1a:8d:
	//          a2:02:20:69:36:11:8c:8c:59:14:9d:ee:56:11:b3:8c:0a:87:
	//          f1:8c:ae:10:e6:da:a7:08:78:6d:36:64:6a:9c:28:0d:94
	TestCertificate1 = `-----BEGIN CERTIFICATE-----
MIIBkzCCATmgAwIBAgIQD3oJqHEJAjT25rEGY6kLgTAKBggqhkjOPQQDAjAwMRUw
EwYDVQQKEwxjZXJ0LW1hbmFnZXIxFzAVBgNVBAMTDmNtY3QtdGVzdC1yb290MB4X
DTIyMTEyNTEzMDM1NFoXDTMyMTEyMjEzMDM1NFowMDEVMBMGA1UEChMMY2VydC1t
YW5hZ2VyMRcwFQYDVQQDEw5jbWN0LXRlc3Qtcm9vdDBZMBMGByqGSM49AgEGCCqG
SM49AwEHA0IABG0axFSG2TE+I2BP2vwdXc79oUCTUewsddgZOq2f+dKjWU5XyPNc
EAxMp37tVjQvsC4cRYEo+uYSmMVcQi4kkVGjNTAzMBIGA1UdEwEB/wQIMAYBAf8C
AQMwHQYDVR0OBBYEFNcEG2uzzT9bczLSnPuEe98nJkVQMAoGCCqGSM49BAMCA0gA
MEUCIQCeN2/Z7jSJJK7m7kcZ/UgJIqbzKS1ktycUQ50+dhqNogIgaTYRjIxZFJ3u
VhGzjAqH8YyuEObapwh4bTZkapwoDZQ=
-----END CERTIFICATE-----`

	// nolint: dupword
	// NB: TestCertificate2 is expected to have the following properties:
	// 1. Same Subject as TestCertificate1
	// 2. Self signed (issuer == subject)
	// There are tests to assert these properties.
	// Certificate:
	//     Data:
	//         Version: 3 (0x2)
	//         Serial Number:
	//             d7:28:b3:57:35:d8:25:d3:0a:6f:2a:c9:9b:68:d8:bb
	//         Signature Algorithm: ED25519
	//         Issuer: O = cert-manager, CN = cmct-test-root
	//         Validity
	//             Not Before: Dec  5 16:22:42 2022 GMT
	//             Not After : Dec  2 16:22:42 2032 GMT
	//         Subject: O = cert-manager, CN = cmct-test-root
	//         Subject Public Key Info:
	//             Public Key Algorithm: ED25519
	//                 ED25519 Public-Key:
	//                 pub:
	//                     5a:35:43:bb:de:3d:e4:a6:78:83:46:05:27:de:23:
	//                     82:01:ab:b7:73:45:5d:69:3a:31:be:75:a4:20:72:
	//                     95:2c
	//         X509v3 extensions:
	//             X509v3 Basic Constraints: critical
	//                 CA:TRUE, pathlen:3
	//             X509v3 Subject Key Identifier:
	//                 58:C2:AA:B4:D5:56:94:11:74:10:0D:2F:38:1D:2B:1D:DA:81:6C:48
	//     Signature Algorithm: ED25519
	//          4a:9b:e4:f9:a1:5e:d9:40:83:24:a2:84:6e:60:94:1c:8e:e5:
	//          96:a3:14:13:41:22:18:ce:17:af:b2:7c:dd:41:a3:95:e3:27:
	//          b6:c6:c1:52:21:1a:84:4f:1c:2b:5b:be:c9:df:b9:0e:72:4b:
	//          3f:79:08:50:f5:04:8b:51:9d:03
	TestCertificate2 = `-----BEGIN CERTIFICATE-----
MIIBVDCCAQagAwIBAgIRANcos1c12CXTCm8qyZto2LswBQYDK2VwMDAxFTATBgNV
BAoTDGNlcnQtbWFuYWdlcjEXMBUGA1UEAxMOY21jdC10ZXN0LXJvb3QwHhcNMjIx
MjA1MTYyMjQyWhcNMzIxMjAyMTYyMjQyWjAwMRUwEwYDVQQKEwxjZXJ0LW1hbmFn
ZXIxFzAVBgNVBAMTDmNtY3QtdGVzdC1yb290MCowBQYDK2VwAyEAWjVDu9495KZ4
g0YFJ94jggGrt3NFXWk6Mb51pCBylSyjNTAzMBIGA1UdEwEB/wQIMAYBAf8CAQMw
HQYDVR0OBBYEFFjCqrTVVpQRdBANLzgdKx3agWxIMAUGAytlcANBAEqb5PmhXtlA
gySihG5glByO5ZajFBNBIhjOF6+yfN1Bo5XjJ7bGwVIhGoRPHCtbvsnfuQ5ySz95
CFD1BItRnQM=
-----END CERTIFICATE-----`

	// Certificate:
	//     Data:
	//         Version: 3 (0x2)
	//         Serial Number:
	//             82:10:cf:b0:d2:40:e3:59:44:63:e0:bb:63:82:8b:00
	//         Signature Algorithm: sha256WithRSAEncryption
	//         Issuer: C = US, O = Internet Security Research Group, CN = ISRG Root X1
	//         Validity
	//             Not Before: Jun  4 11:04:38 2015 GMT
	//             Not After : Jun  4 11:04:38 2035 GMT
	//         Subject: C = US, O = Internet Security Research Group, CN = ISRG Root X1
	//         Subject Public Key Info:
	//             Public Key Algorithm: rsaEncryption
	//                 RSA Public-Key: (4096 bit)
	//                 Modulus:
	//                     00:ad:e8:24:73:f4:14:37:f3:9b:9e:2b:57:28:1c:
	//                     <snip>
	//                     33:43:4f
	//                 Exponent: 65537 (0x10001)
	//         X509v3 extensions:
	//             X509v3 Key Usage: critical
	//                 Certificate Sign, CRL Sign
	//             X509v3 Basic Constraints: critical
	//                 CA:TRUE
	//             X509v3 Subject Key Identifier:
	//                 79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E
	//     Signature Algorithm: sha256WithRSAEncryption
	//          55:1f:58:a9:bc:b2:a8:50:d0:0c:b1:d8:1a:69:20:27:29:08:
	//          <snip>
	//          9d:7e:62:22:da:de:18:27
	TestCertificate3 = `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----`

	// Certificate:
	//     Data:
	//         Version: 3 (0x2)
	//         Serial Number:
	//             41:d2:9d:d1:72:ea:ee:a7:80:c1:2c:6c:e9:2f:87:52
	//         Signature Algorithm: ecdsa-with-SHA384
	//         Issuer: C = US, O = Internet Security Research Group, CN = ISRG Root X2
	//         Validity
	//             Not Before: Sep  4 00:00:00 2020 GMT
	//             Not After : Sep 17 16:00:00 2040 GMT
	//         Subject: C = US, O = Internet Security Research Group, CN = ISRG Root X2
	//         Subject Public Key Info:
	//             Public Key Algorithm: id-ecPublicKey
	//                 Public-Key: (384 bit)
	//                 pub:
	//                     04:cd:9b:d5:9f:80:83:0a:ec:09:4a:f3:16:4a:3e:
	//                     5c:cf:77:ac:de:67:05:0d:1d:07:b6:dc:16:fb:5a:
	//                     8b:14:db:e2:71:60:c4:ba:45:95:11:89:8e:ea:06:
	//                     df:f7:2a:16:1c:a4:b9:c5:c5:32:e0:03:e0:1e:82:
	//                     18:38:8b:d7:45:d8:0a:6a:6e:e6:00:77:fb:02:51:
	//                     7d:22:d8:0a:6e:9a:5b:77:df:f0:fa:41:ec:39:dc:
	//                     75:ca:68:07:0c:1f:ea
	//                 ASN1 OID: secp384r1
	//                 NIST CURVE: P-384
	//         X509v3 extensions:
	//             X509v3 Key Usage: critical
	//                 Certificate Sign, CRL Sign
	//             X509v3 Basic Constraints: critical
	//                 CA:TRUE
	//             X509v3 Subject Key Identifier:
	//                 7C:42:96:AE:DE:4B:48:3B:FA:92:F8:9E:8C:CF:6D:8B:A9:72:37:95
	//     Signature Algorithm: ecdsa-with-SHA384
	//          30:65:02:30:7b:79:4e:46:50:84:c2:44:87:46:1b:45:70:ff:
	//          58:99:de:f4:fd:a4:d2:55:a6:20:2d:74:d6:34:bc:41:a3:50:
	//          5f:01:27:56:b4:be:27:75:06:af:12:2e:75:98:8d:fc:02:31:
	//          00:8b:f5:77:6c:d4:c8:65:aa:e0:0b:2c:ee:14:9d:27:37:a4:
	//          f9:53:a5:51:e4:29:83:d7:f8:90:31:5b:42:9f:0a:f5:fe:ae:
	//          00:68:e7:8c:49:0f:b6:6f:5b:5b:15:f2:e7
	TestCertificate4 = `-----BEGIN CERTIFICATE-----
MIICGzCCAaGgAwIBAgIQQdKd0XLq7qeAwSxs6S+HUjAKBggqhkjOPQQDAzBPMQsw
CQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2gg
R3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBYMjAeFw0yMDA5MDQwMDAwMDBaFw00
MDA5MTcxNjAwMDBaME8xCzAJBgNVBAYTAlVTMSkwJwYDVQQKEyBJbnRlcm5ldCBT
ZWN1cml0eSBSZXNlYXJjaCBHcm91cDEVMBMGA1UEAxMMSVNSRyBSb290IFgyMHYw
EAYHKoZIzj0CAQYFK4EEACIDYgAEzZvVn4CDCuwJSvMWSj5cz3es3mcFDR0HttwW
+1qLFNvicWDEukWVEYmO6gbf9yoWHKS5xcUy4APgHoIYOIvXRdgKam7mAHf7AlF9
ItgKbppbd9/w+kHsOdx1ymgHDB/qo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUfEKWrt5LSDv6kviejM9ti6lyN5UwCgYIKoZI
zj0EAwMDaAAwZQIwe3lORlCEwkSHRhtFcP9Ymd70/aTSVaYgLXTWNLxBo1BfASdW
tL4ndQavEi51mI38AjEAi/V3bNTIZargCyzuFJ0nN6T5U6VR5CmD1/iQMVtCnwr1
/q4AaOeMSQ+2b1tbFfLn
-----END CERTIFICATE-----`

	// Certificate:
	//     Data:
	//         Version: 3 (0x2)
	//         Serial Number:
	//             02:03:e5:93:6f:31:b0:13:49:88:6b:a2:17
	//         Signature Algorithm: sha384WithRSAEncryption
	//         Issuer: C = US, O = Google Trust Services LLC, CN = GTS Root R1
	//         Validity
	//             Not Before: Jun 22 00:00:00 2016 GMT
	//             Not After : Jun 22 00:00:00 2036 GMT
	//         Subject: C = US, O = Google Trust Services LLC, CN = GTS Root R1
	//         Subject Public Key Info:
	//             Public Key Algorithm: rsaEncryption
	//                 RSA Public-Key: (4096 bit)
	//                 Modulus:
	//                     00:b6:11:02:8b:1e:e3:a1:77:9b:3b:dc:bf:94:3e:
	//                     <snip>
	//                     18:05:95
	//                 Exponent: 65537 (0x10001)
	//         X509v3 extensions:
	//             X509v3 Key Usage: critical
	//                 Digital Signature, Certificate Sign, CRL Sign
	//             X509v3 Basic Constraints: critical
	//                 CA:TRUE
	//             X509v3 Subject Key Identifier:
	//                 E4:AF:2B:26:71:1A:2B:48:27:85:2F:52:66:2C:EF:F0:89:13:71:3E
	//     Signature Algorithm: sha384WithRSAEncryption
	//          9f:aa:42:26:db:0b:9b:be:ff:1e:96:92:2e:3e:a2:65:4a:6a:
	//          <snip>
	//          71:ae:57:fb:b7:82:6d:dc
	TestCertificate5 = `-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw
MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo
27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w
Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw
TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl
qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH
szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8
Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk
MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92
wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p
aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN
VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID
AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb
C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe
QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy
h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4
7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J
ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef
MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/
Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT
6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ
0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm
2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb
bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c
-----END CERTIFICATE-----`

	// DUPLICATE CERTIFICATE
	// Certificate:
	//
	//	Data:
	//	    Version: 3 (0x2)
	//	    Serial Number:
	//	        02:03:e5:93:6f:31:b0:13:49:88:6b:a2:17
	//	    Signature Algorithm: sha384WithRSAEncryption
	//	    Issuer: C = US, O = Google Trust Services LLC, CN = GTS Root R1
	//	    Validity
	//	        Not Before: Jun 22 00:00:00 2016 GMT
	//	        Not After : Jun 22 00:00:00 2036 GMT
	//	    Subject: C = US, O = Google Trust Services LLC, CN = GTS Root R1
	//	    Subject Public Key Info:
	//	        Public Key Algorithm: rsaEncryption
	//	            RSA Public-Key: (4096 bit)
	//	            Modulus:
	//	                00:b6:11:02:8b:1e:e3:a1:77:9b:3b:dc:bf:94:3e:
	//	                <snip>
	//	                18:05:95
	//	            Exponent: 65537 (0x10001)
	//	    X509v3 extensions:
	//	        X509v3 Key Usage: critical
	//	            Digital Signature, Certificate Sign, CRL Sign
	//	        X509v3 Basic Constraints: critical
	//	            CA:TRUE
	//	        X509v3 Subject Key Identifier:
	//	            E4:AF:2B:26:71:1A:2B:48:27:85:2F:52:66:2C:EF:F0:89:13:71:3E
	//	Signature Algorithm: sha384WithRSAEncryption
	//	     9f:aa:42:26:db:0b:9b:be:ff:1e:96:92:2e:3e:a2:65:4a:6a:
	//	     <snip>
	//	     71:ae:57:fb:b7:82:6d:dc
	TestCertificate5Duplicate = `-----BEGIN CERTIFICATE-----
MIIFVzCCAz+gAwIBAgINAgPlk28xsBNJiGuiFzANBgkqhkiG9w0BAQwFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMTYwNjIyMDAwMDAwWhcNMzYwNjIyMDAw
MDAwWjBHMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzEUMBIGA1UEAxMLR1RTIFJvb3QgUjEwggIiMA0GCSqGSIb3DQEBAQUA
A4ICDwAwggIKAoICAQC2EQKLHuOhd5s73L+UPreVp0A8of2C+X0yBoJx9vaMf/vo
27xqLpeXo4xL+Sv2sfnOhB2x+cWX3u+58qPpvBKJXqeqUqv4IyfLpLGcY9vXmX7w
Cl7raKb0xlpHDU0QM+NOsROjyBhsS+z8CZDfnWQpJSMHobTSPS5g4M/SCYe7zUjw
TcLCeoiKu7rPWRnWr4+wB7CeMfGCwcDfLqZtbBkOtdh+JhpFAz2weaSUKK0Pfybl
qAj+lug8aJRT7oM6iCsVlgmy4HqMLnXWnOunVmSPlk9orj2XwoSPwLxAwAtcvfaH
szVsrBhQf4TgTM2S0yDpM7xSma8ytSmzJSq0SPly4cpk9+aCEI3oncKKiPo4Zor8
Y/kB+Xj9e1x3+naH+uzfsQ55lVe0vSbv1gHR6xYKu44LtcXFilWr06zqkUspzBmk
MiVOKvFlRNACzqrOSbTqn3yDsEB750Orp2yjj32JgfpMpf/VjsPOS+C12LOORc92
wO1AK/1TD7Cn1TsNsYqiA94xrcx36m97PtbfkSIS5r762DL8EGMUUXLeXdYWk70p
aDPvOmbsB4om3xPXV2V4J95eSRQAogB/mqghtqmxlbCluQ0WEdrHbEg8QOB+DVrN
VjzRlwW5y0vtOUucxD/SVRNuJLDWcfr0wbrM7Rv1/oFB2ACYPTrIrnqYNxgFlQID
AQABo0IwQDAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQU5K8rJnEaK0gnhS9SZizv8IkTcT4wDQYJKoZIhvcNAQEMBQADggIBAJ+qQibb
C5u+/x6Wki4+omVKapi6Ist9wTrYggoGxval3sBOh2Z5ofmmWJyq+bXmYOfg6LEe
QkEzCzc9zolwFcq1JKjPa7XSQCGYzyI0zzvFIoTgxQ6KfF2I5DUkzps+GlQebtuy
h6f88/qBVRRiClmpIgUxPoLW7ttXNLwzldMXG+gnoot7TiYaelpkttGsN/H9oPM4
7HLwEXWdyzRSjeZ2axfG34arJ45JK3VmgRAhpuo+9K4l/3wV3s6MJT/KYnAK9y8J
ZgfIPxz88NtFMN9iiMG1D53Dn0reWVlHxYciNuaCp+0KueIHoI17eko8cdLiA6Ef
MgfdG+RCzgwARWGAtQsgWSl4vflVy2PFPEz0tv/bal8xa5meLMFrUKTX5hgUvYU/
Z6tGn6D/Qqc6f1zLXbBwHSs09dR2CQzreExZBfMzQsNhFRAbd03OIozUhfJFfbdT
6u9AWpQKXCBfTkBdYiJ23//OYb2MI3jSNwLgjt7RETeJ9r/tSQdirpLsQBqvFAnZ
0E6yove+7u7Y/9waLd64NnHi/Hm3lCXRSHNboTXns5lndcEZOitHTtNCjv0xyBZm
2tIMPNuzjsmhDYAPexZ3FL//2wmUspO8IFgV6dtxQ/PeEMMA3KgqlbbC1j+Qa3bb
bP6MvPJwNQzcmRk13NfIRmPVNnGuV/u3gm3c
-----END CERTIFICATE-----`

	// DUPLICATE CERTIFICATE
	// Certificate:
	//     Data:
	//         Version: 3 (0x2)
	//         Serial Number:
	//             82:10:cf:b0:d2:40:e3:59:44:63:e0:bb:63:82:8b:00
	//         Signature Algorithm: sha256WithRSAEncryption
	//         Issuer: C = US, O = Internet Security Research Group, CN = ISRG Root X1
	//         Validity
	//             Not Before: Jun  4 11:04:38 2015 GMT
	//             Not After : Jun  4 11:04:38 2035 GMT
	//         Subject: C = US, O = Internet Security Research Group, CN = ISRG Root X1
	//         Subject Public Key Info:
	//             Public Key Algorithm: rsaEncryption
	//                 RSA Public-Key: (4096 bit)
	//                 Modulus:
	//                     00:ad:e8:24:73:f4:14:37:f3:9b:9e:2b:57:28:1c:
	//                     <snip>
	//                     33:43:4f
	//                 Exponent: 65537 (0x10001)
	//         X509v3 extensions:
	//             X509v3 Key Usage: critical
	//                 Certificate Sign, CRL Sign
	//             X509v3 Basic Constraints: critical
	//                 CA:TRUE
	//             X509v3 Subject Key Identifier:
	//                 79:B4:59:E6:7B:B6:E5:E4:01:73:80:08:88:C8:1A:58:F6:E9:9B:6E
	//     Signature Algorithm: sha256WithRSAEncryption
	//          55:1f:58:a9:bc:b2:a8:50:d0:0c:b1:d8:1a:69:20:27:29:08:
	//          <snip>
	//          9d:7e:62:22:da:de:18:27
	TestCertificate3Duplicate = `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----`
	// Invalid certificate
	TestCertificateInvalid7 = `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW`
	// Expired certificate
	// Certificate:
	// Data:
	//     Version: 3 (0x2)
	//     Serial Number:
	//         7c:76:92:2b:61:63:6e:68:28:3b:5c:38:db:dc:9a:92:bd:85:75:c1
	//     Signature Algorithm: sha256WithRSAEncryption
	//     Issuer: C = AU, ST = Some-State, O = Internet Widgits Pty Ltd
	//     Validity
	//         Not Before: Jan  6 11:09:24 2024 GMT
	//         Not After : Jan 12 11:09:24 2024 GMT
	TestExpiredCertificate = `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIUfHaSK2FjbmgoO1w429yakr2FdcEwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDAxMDYxMTA5MjRaFw0yNDAx
MTIxMTA5MjRaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDCBBPhZNW/sADtNAL97H3jcXB39mpRr9coeFUlxY8w
+WaHJyAbVX0+k1ZYbKSOp7R4gWVNNLSKwEG/BlAUg6YM+gJsw6kuHmXfidVLLLnr
dLOy+mjU3Ogr04JEa9YbG8WyVpyLIeshfTvZkK58XBOagKI/mxN48W8abGz6o/Xv
0pxtNiHkczd2F1cPPwid4EZ3rKl3RgzeEctVjvfN0iZhz0piyft8wzhaYisDdcw2
yzQdyT4NsUmE8RWZmiFzyoN+Sn3yGX7lKvrw0LbuF0agtC7Ainz/zQ1NApcnL4le
YonLJHH3Gwmk9UNFn/kH1QQXAkHJ5Miyfek5fk/eR3C+4dDdMDswg/PBni8GVigX
lnNlUqL5BvQJ3dGNdA02UWZ4TCQ1slx33cjUxCvfTgu6rT+uaEIsWTO8NcSyRM7k
Wmd11Mg40adrga2r+iR6zvmSZ+qfzWnyNAwLIefg4Fq9KD+A8qj41D2ukx6aKUuh
j80VqkBoJ0sP7dA2g2wJuxmlLOLqiMB8lZofKRfXUdFHXdwZ9O6+Co87ZpBEYBmP
7b1IgVC0Ereo9Z0ZaoK5UgKGFP/D+usbLX+e5HjPt1bpJhJnrad0KrXklRqKe1wg
jpVEVgbsRu5L+rLzL//k/PtMZoq+e1HAzTiNl+GL91fR4vbLTWQt5yeTVO30f5Mq
SwIDAQABo1MwUTAdBgNVHQ4EFgQUZekjV6TRymiFzE2svIIcIpXusuMwHwYDVR0j
BBgwFoAUZekjV6TRymiFzE2svIIcIpXusuMwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEAJnN62sYly65vV/pAJpmOZRU7oFokWC8t3TxS11uPFqjs
hzPgBZPIVyHbBip8QQamPIEfx5P2zLa97ujV8LtHsjNwoFIDfydUtxo6G+yAX0nL
iq71a3jz1wZu7n5wOVUK1EMieY0qm3P+9LSO4dIwVrLuLV3bNKO4Ey3vKSc5OQdN
I4Z4pip/0RUoW3BVeQoSGSm07WquRI92hM63q1iwShaBZcy4e9w6Qi5MDSMZgfbo
gkgj8ezlUveC0ZXvdRCS8i47M4DxLwX95HWUE9ZnKVFMwz60AI5VlYGdt8HJigHE
dzuTIyGToa98LO8yBD9OehBaDQsj6PTDyFiiLVkkCcjVwC+O2ShkQVoCS4ELOoKc
JI0RHMMtisPfPO9bQmPYrEI7w4qG31g1iUEWCposO0slPDHONLnja8bF9R7RbfyO
PQ5qEvRB3rGmtpvWu/p8z4AlMSWFb9C+Qp4NiU2jiPgw0t1DL/vdrvLcYb/ExyJx
/+ZA+ONCt347Do/oMXy8iT4cmNOe28pHLYHkhkbP5d2ajpjSwqH2Q8Gr8AiMM5OO
HYjDRRens0uEsJFTfFBq0YbGiIAHZ1ESs/ipdisdgmLkIDjF8UKRNoBacodAsghV
z40l74JcR+GvcFZWz7/jmJq95YMZ7LawLAr1CaAXxCwsoLbJpbgg4lVo6odACzY=
-----END CERTIFICATE-----`

	// Certificate:
	//     Data:
	//         Version: 3 (0x2)
	//         Serial Number:
	//             67:bc:27:4c:38:bd:86:8e:64:64:b9:bc:e7:96:c6:fa:4e:78:57:a4
	//         Signature Algorithm: sha256WithRSAEncryption
	//         Issuer: C=US, L=Default City, O=Internet Security Research Group, CN=www.example.com
	//         Validity
	//             Not Before: Dec 20 15:32:26 2025 GMT
	//             Not After : Dec 18 15:32:26 2035 GMT
	//         Subject: C=US, L=Default City, O=Internet Security Research Group, CN=www.example.com
	//         Subject Public Key Info:
	//             Public Key Algorithm: rsaEncryption
	//                 Public-Key: (4096 bit)
	//                 Modulus:
	//                     00:a9:7c:2d:2a:b1:67:0e:90:f8:37:db:c4:d7:7b:
	//                     7b:00:40:72:8e:d9:44:70:b0:96:38:4c:4f:91:9f:
	//										 ...
	//                     56:c9:bc:07:0f:87:f3:10:75:0e:3d:3a:1e:83:cc:
	//                     61:4d:fb
	//                 Exponent: 65537 (0x10001)
	//         X509v3 extensions:
	//             X509v3 Subject Key Identifier:
	//                 6F:F8:A7:F7:66:75:D9:EB:02:25:05:A4:4E:62:C5:D9:85:53:F9:0B
	//             X509v3 Authority Key Identifier:
	//                 6F:F8:A7:F7:66:75:D9:EB:02:25:05:A4:4E:62:C5:D9:85:53:F9:0B
	//             X509v3 Basic Constraints:
	//                 CA:FALSE
	TestCertificateNonCA1 = `-----BEGIN CERTIFICATE-----
MIIFrTCCA5WgAwIBAgIUZ7wnTDi9ho5kZLm855bG+k54V6QwDQYJKoZIhvcNAQEL
BQAwaTELMAkGA1UEBhMCVVMxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEpMCcGA1UE
CgwgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxGDAWBgNVBAMMD3d3
dy5leGFtcGxlLmNvbTAeFw0yNTEyMjAxNTMyMjZaFw0zNTEyMTgxNTMyMjZaMGkx
CzAJBgNVBAYTAlVTMRUwEwYDVQQHDAxEZWZhdWx0IENpdHkxKTAnBgNVBAoMIElu
dGVybmV0IFNlY3VyaXR5IFJlc2VhcmNoIEdyb3VwMRgwFgYDVQQDDA93d3cuZXhh
bXBsZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCpfC0qsWcO
kPg328TXe3sAQHKO2URwsJY4TE+Rn99jMHtMwHtgmxPQ/sMlljrhPk5vdf55i0R9
iWm9sEvRynhv2hejr2hV0RAM7Q2+Q4We9Qmn8Bh9+sN60I5YVM1lOmVKUbxDQTFm
D1WrC3NMLuAhnkoJKE1ElAN3f6TWihWhlg4lmN8qbFcZIsGMXmEKXiPPFLqTn0h7
G5HTo0SCOqQnG4qdIW4hdOXVb3dIeX5/yVeKwQJcUWrIcOSONG5SAfbwvUFExp7d
10g/j5r4wWGvvzm9pJzpMLgGCwMoATxHdM7k2twSbIIrulfmCgiqzqqmctUEP3c4
AYbPr/LDtlRqEGxFHlfmnpT9nDETF44enBEeQ75tsj7sguqNOay+/lemM42SnfSt
mrcm14LAvZtpV5+zeyxA4ujczsUybWuWM6jtmRaBbQ4MtPCG3q+GMyroMtJ+AXYH
1sM67AppyTNaxYf5bns+mdCKce9BrOM1Uqqh8R0hikoVTW65WhDdh+iJHU9DAbvC
mIW5NDeyevs/utI3hppLZZ1dyhrQ5U1CjrWZ63sEjy0InCF4OJg8Ck4d8HYe1Ipk
I16pRBe9FAd0AvOZgUXE18o5si6LOOEWkAkf9aw3+CeUs3ijRmsg2vFWgivoz4uE
w8L7+b2cQFbJvAcPh/MQdQ49Oh6DzGFN+wIDAQABo00wSzAdBgNVHQ4EFgQUb/in
92Z12esCJQWkTmLF2YVT+QswHwYDVR0jBBgwFoAUb/in92Z12esCJQWkTmLF2YVT
+QswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsFAAOCAgEAfgAjHMI8Kt7uVxvRWo8W
DzmYT7FJYWxBGEng7DJcvb346C9o3Bo/4HDG4t0G/COwpbO5k/7GY9WmOCTi7hD9
s5itXH2Oxvnn2Vmnyf0ZcbzFnJWN7sHHvqB7HBCVCmJdzp1etjr7klXUalIRPp9w
Xpv6XUKBCRAWDVvIiZOfeTHrmF1GHcsbBiSZKn/sD7HbgOY4eHFbwWjEtOynW3i4
YBDmd7IZlUnxUJEGFq+8wuFt1QpjtzZp+zD2ZLKE2hdzoUmIWNPPWtrplvP68yTY
KGtggpbG4rTmaq4C7Y2g56hAbWARgtwa52keGl42vBeIoY6uDuByQG1+uxJlkRhh
vKKL8Nv1Bvv1QBpFZa3WckRbe+vUl+4lWQsaHWjydrv//rxTpKw7NO+y2O5YYwgz
kX7dbrSluYP9KjvawopYqaN362QA+ZDkq17u2jF0H3l78IMoVTEszEME5VF9GuP6
EeuzMl8ttrIwZig/t7TSpVzGyxbNAE2CJQ5Ydt22AaLnZX2BXiBRCNxmi58j/fBH
1dIomzU1yZwcXZwUCga0j9+xEhdG8gdr77G4O0P1BO8Tui6WeNU3DAWWWiuBLWT6
K6WVn0GVZR2gMUZs6Fdi1f5pguIQE10be9VM+m2ei9Cy3rjZLnAKN87D2JJJPm8C
plNZGnaNc9ms+ZvMgFUOQOQ=
-----END CERTIFICATE-----`

	// Certificate:
	//     Data:
	//         Version: 3 (0x2)
	//         Serial Number:
	//             26:0f:0c:cd:09:53:87:27:55:51:74:7b:d9:4e:c4:e1:ea:cd:6d:2c
	//         Signature Algorithm: sha256WithRSAEncryption
	//         Issuer: C=US, L=Default City, O=Internet Security Research Group, CN=mail.example.com
	//         Validity
	//             Not Before: Dec 20 15:36:45 2025 GMT
	//             Not After : Dec 18 15:36:45 2035 GMT
	//         Subject: C=US, L=Default City, O=Internet Security Research Group, CN=mail.example.com
	//         Subject Public Key Info:
	//             Public Key Algorithm: rsaEncryption
	//                 Public-Key: (4096 bit)
	//                 Modulus:
	//                     00:b6:81:5f:a9:f3:19:1f:a6:71:56:61:e6:53:e9:
	//                     8f:24:f4:05:4f:06:25:a9:8b:f3:4f:b3:82:9a:dd:
	//										 ...
	//                     c8:d1:ca:45:84:69:8e:f6:1d:bb:e0:43:24:73:7c:
	//                     2f:08:bd
	//                 Exponent: 65537 (0x10001)
	//         X509v3 extensions:
	//             X509v3 Subject Key Identifier:
	//                 43:3E:01:3D:F9:34:CE:19:31:8A:F1:2F:82:68:CD:1D:F5:A8:61:87
	//             X509v3 Authority Key Identifier:
	//                 43:3E:01:3D:F9:34:CE:19:31:8A:F1:2F:82:68:CD:1D:F5:A8:61:87
	//             X509v3 Basic Constraints:
	//                 CA:FALSE
	TestCertificateNonCA2 = `-----BEGIN CERTIFICATE-----
MIIFrzCCA5egAwIBAgIUJg8MzQlThydVUXR72U7E4erNbSwwDQYJKoZIhvcNAQEL
BQAwajELMAkGA1UEBhMCVVMxFTATBgNVBAcMDERlZmF1bHQgQ2l0eTEpMCcGA1UE
CgwgSW50ZXJuZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxGTAXBgNVBAMMEG1h
aWwuZXhhbXBsZS5jb20wHhcNMjUxMjIwMTUzNjQ1WhcNMzUxMjE4MTUzNjQ1WjBq
MQswCQYDVQQGEwJVUzEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MSkwJwYDVQQKDCBJ
bnRlcm5ldCBTZWN1cml0eSBSZXNlYXJjaCBHcm91cDEZMBcGA1UEAwwQbWFpbC5l
eGFtcGxlLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALaBX6nz
GR+mcVZh5lPpjyT0BU8GJamL80+zgprdJ/Xq1aMB709asF3o/gWlHVMke2JIX+lr
kvQLoSxr0AB7eOwaz+8KfWH3BLw399j9c88Lo+ZAot8CgpUz7YaeETOUveEGJVSb
PP/k0bmNxqBPnP3ba20xTRlW5MFnTXHxNJ5TghRC98FfeGwEkN8tb5YdFzoRKM/m
FSRevS4rcHBIwpU4l9xNIBfgI7P/Ib/UlrXTITVdAMriypU3AkNn25cUECa4sJ5a
YVvI/bv4r63x8gscFVwhleM5Ms9eENoAF/BbZq2Fc/la2DwZANkaq1WOz0us5NS2
UzIIhKM9OU/+FbPs1x2UiAjGLa5X/HVE2Y0HJx0JzAEb4jMaDHn1KoE2HImWCp5F
RdS2VEAJKoH0Dv6toP//exK/uQoQs3c/V668Dm4yRERWJ42ipeSHrVNkkwUSKgvp
qD2oaaE8CGgXunraE5hbKb4zOy/xBiw6FVdOZ3fyNGlWZ38lvUDLVjyK4GdKEWN5
b6T098qmUfl4vflAxvL0NeGb8zvT2n12REWbtSpPFjp2Tq+fBcPCq1OE3zDsca4d
hwiVNJ33O5VVhqnVd20VlAo+IxHi+IhdIotMhHnhXi0+86i/aRTTiUO2/h/BoHWK
zYp6VSKAFUu2yNHKRYRpjvYdu+BDJHN8Lwi9AgMBAAGjTTBLMB0GA1UdDgQWBBRD
PgE9+TTOGTGK8S+CaM0d9ahhhzAfBgNVHSMEGDAWgBRDPgE9+TTOGTGK8S+CaM0d
9ahhhzAJBgNVHRMEAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQA12GwhzZfNQBWbWmk1
2E6JdQFrsRIcgkHo54eyhoIjLsHKrwP99DcHTTFrOfJPrGRk5b/C8mnNlcQOey+I
qmpRrwvpvW4njxPR5bUzt4UsOrG7k+GsA4ovQzjvDCAdjLcvoFFYrMvoQ18rvxEH
NuJeRoqc5bnSO0k+B5lc9TCsfHQwLkw7s6K8l2scdJj7X0vg2KTn0FDRMQlvWcBK
lxbfHTDGK2+N841TIABalhT1ljMlhnfdDiVQGqRnmVdrTM4diJ1CaRm7CW36CwCE
yeYLc5Q/hdNd3AlsZo4Wu9xnjW5ozeoOKveJrm1KSl+BylkF+bHWFaq1w7EDQkVC
uv0BEdFyXcFL7sI3OsblXJibSqZJsZn/SeJja3LAvm5M5FIjoZ1uZzzdc0Hx1tzb
OdjK0cgXqcyz/stQ22kKnadZOi0lMoVUmP8TLo+2B6LvAYHClStEIhBet2W80wDe
PwfVKfLQ98Fpt7QHzpzcwje2I3dfyI1WHNPptJcryFdXcJHLHksv1rk+tbcaHN8K
rsE6P1NCjsAFn43+Kicmlj14IR1UZ54MmK+KXlr1I2/MAXvI86rXhTXC7xI+uS5v
/qf5aom1SWBJAQmexwbC+viyH/obwSNAygLNTyUBOx9TSPlsEazQ8TV+9OaWkbsh
rtDOMVCUoMGIbAJRLwKLL7djlw==
-----END CERTIFICATE-----`
)

func DefaultJoinedCerts() string {
	return JoinCerts(
		TestCertificate2,
		TestCertificate1,
		TestCertificate3,
	)
}

func JoinCerts(certs ...string) string {
	return strings.Join(certs, "\n")
}
