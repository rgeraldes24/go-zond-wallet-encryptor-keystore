package keystorev1_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	keystorev1 "github.com/theQRL/go-zond-wallet-encryptor-keystore"
)

func TestEncrypt(t *testing.T) {
	tests := []struct {
		name       string
		cipher     string
		secret     []byte
		passphrase string
		err        error
	}{
		{
			name:       "BlankCustomKDF",
			cipher:     "custom",
			secret:     []byte{},
			passphrase: "",
		},
		{
			name:       "InvalidCipher",
			cipher:     "cipher-1212",
			secret:     []byte{},
			passphrase: "",
			err:        errors.New(`invalid cipher cipher-1212`),
		},
		{
			name:   "Valid",
			cipher: "custom",
			secret: []byte{
				0xa0, 0x77, 0x66, 0x11, 0xef, 0x05, 0x06, 0xab, 0xe1, 0xb9, 0x3d, 0x4f, 0xae, 0x09, 0x11, 0x22,
				0xbe, 0x88, 0x55, 0x22, 0xcd, 0x15, 0x16, 0xba, 0xda, 0xd2, 0x51, 0xc9, 0x00, 0x22, 0x98, 0x33,
				0x0e, 0x99, 0x44, 0x33, 0xab, 0x25, 0x26, 0xef, 0xdc, 0xc4, 0x24, 0x41, 0x68, 0x33, 0x66, 0x44,
			},
			passphrase: "mybigpassword--123",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var options []keystorev1.Option
			if test.cipher != "" {
				options = append(options, keystorev1.WithCipher(test.cipher))
			}
			encryptor := keystorev1.New(options...)
			_, err := encryptor.Encrypt(test.secret, test.passphrase)
			if test.err != nil {
				require.NotNil(t, err)
				assert.Equal(t, test.err.Error(), err.Error())
			} else {
				require.Nil(t, err)
			}
		})
	}
}
