package keystorev1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Encrypt encrypts data.
func (e *Encryptor) Encrypt(data []byte, passphrase string) (map[string]interface{}, error) {
	// Random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	var decryptionKey []byte
	var err error
	switch e.cipher {
	case "custom":
		decryptionKey, err = passwordToDecryptionKey(passphrase, salt)
	default:
		return nil, fmt.Errorf("invalid cipher %s", e.cipher)
	}
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(decryptionKey)
	if err != nil {
		return nil, err
	}

	//cipherMsg := make([]byte, len(seed))
	aesIV := make([]byte, 12)
	if _, err := rand.Read(aesIV); err != nil {
		return nil, err
	}

	cipherText := make([]byte, len(data))
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aesgcm.Seal(cipherText, aesIV, data, nil)

	var kdf *_kdf
	switch e.cipher {
	case "custom":
		kdf = &_kdf{
			Function: "custom",
			Params: &paramsKDF{
				Salt: hex.EncodeToString(salt),
			},
			Message: "",
		}
	}

	output := &keystoreV1{
		KDF: kdf,
		Cipher: &_cipher{
			Function: "aes-256-gcm",
			Params: &paramsCipher{
				IV: hex.EncodeToString(aesIV),
			},
			Message: hex.EncodeToString(cipherText),
		},
	}

	bytes, err := json.Marshal(output)
	if err != nil {
		return nil, err
	}
	res := make(map[string]interface{})
	err = json.Unmarshal(bytes, &res)
	if err != nil {
		return nil, err
	}

	return res, nil
}
