package keystorev1_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keystorev1 "github.com/theQRL/go-zond-wallet-encryptor-keystore"
	zondtypes "github.com/theQRL/go-zond-wallet-types"
)

func TestInterfaces(t *testing.T) {
	encryptor := keystorev1.New()
	require.Implements(t, (*zondtypes.Encryptor)(nil), encryptor)
}

func TestRoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		passphrase string
		secret     []byte
		options    []keystorev1.Option
		err        error
	}{
		{
			name:       "Test1",
			input:      `{"cipher":{"function":"aes-256-gcm","message":"c179fe7679a4756ac7ea044458c76e330d49bb85c6cc810ff60fcee8294a5886","params":{"iv":"179c9689b7252836c2a449e63544b222"}},"kdf":{"function":"custom","message":"","params":{"salt":"b518a4d4ff18959eaef9f93d247d707945829a81c2d10983b65af6beb43d09ce"}}}`,
			passphrase: "1234password",
			secret:     []byte{0x0, 0xfc, 0xd5, 0xa5, 0x80, 0x43, 0x39, 0xb6, 0xd8, 0xd4, 0x51, 0x7a, 0xd7, 0x3e, 0x4e, 0x86, 0x6f, 0xaf, 0xbe, 0x41, 0x98, 0xd0, 0xbc, 0xc7, 0x5, 0xef, 0x95, 0x33, 0x41, 0x7d, 0x72, 0x2c},
		},
		{
			name:       "Test2",
			input:      `{"kdf":{"function":"custom","params":{"salt":"b518a4d4ff18959eaef9f93d247d707945829a81c2d10983b65af6beb43d09ce"},"message":""},"cipher":{"function":"aes-256-gcm","params":{"iv":"f0f7891dcfb9a6b534cc36491038f7e4"},"message":"5b2349913e020266c82c93564ba32678999d6e22160530f8cc0f256a7e6ba0dd"}}`,
			passphrase: "!!99338@@00",
			secret:     []byte{0x94, 0x45, 0x6b, 0x3f, 0x20, 0xf6, 0x46, 0xac, 0x2d, 0x15, 0x14, 0xb2, 0x6a, 0x2a, 0x56, 0xb, 0xb0, 0xbc, 0xe9, 0xa1, 0x6b, 0x75, 0xd6, 0xd4, 0x98, 0xfd, 0x63, 0xb1, 0xb6, 0xb8, 0x37, 0x4a},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encryptor := keystorev1.New(test.options...)
			input := make(map[string]any)
			err := json.Unmarshal([]byte(test.input), &input)
			require.Nil(t, err)
			secret, err := encryptor.Decrypt(input, test.passphrase)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
				require.Equal(t, test.secret, secret)
				newInput, err := encryptor.Encrypt(secret, test.passphrase)
				require.Nil(t, err)
				newSecret, err := encryptor.Decrypt(newInput, test.passphrase)
				require.Nil(t, err)
				require.Equal(t, test.secret, newSecret)
			}
		})
	}
}

func TestNameAndVersion(t *testing.T) {
	encryptor := keystorev1.New()
	assert.Equal(t, "keystore", encryptor.Name())
	assert.Equal(t, uint(1), encryptor.Version())
	assert.Equal(t, "keystorev1", encryptor.String())
}

func TestGenerateKey(t *testing.T) {
	encryptor := keystorev1.New()
	x, err := encryptor.Encrypt([]byte{0xaa, 0xff, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x12, 0x23, 0x45, 0x67, 0x78, 0xe9, 0x42, 0x61, 0x71, 0x9d, 0x3d, 0x4d, 0x5e, 0xff, 0xfc, 0xcc, 0xae, 0xea, 0x82, 0x21, 0x05, 0x01, 0x74, 0x32}, "")
	require.Nil(t, err)
	assert.NotNil(t, x)
}
