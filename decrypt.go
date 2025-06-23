package keystorev1

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/theQRL/go-zond-wallet-encryptor-keystore/misc"
	"golang.org/x/crypto/sha3"
)

func passwordToDecryptionKey(password string, salt []byte) ([]byte, error) {
	h := sha3.NewShake256()
	if _, err := h.Write([]byte(password)); err != nil {
		return []byte{}, fmt.Errorf("shake256 hash write failed %v", err)
	}

	if _, err := h.Write(salt); err != nil {
		return []byte{}, fmt.Errorf("shake256 hash write failed %v", err)
	}

	var decryptionKey [32]uint8
	_, err := h.Read(decryptionKey[:])
	return decryptionKey[:], err
}

func (e *Encryptor) Decrypt(data map[string]interface{}, passphrase string) ([]byte, error) {
	if data == nil {
		return nil, errors.New("data cannot be nil")
	}

	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("keystore cannot be parsed | reason %v", err)
	}
	ks := &keystoreV1{}
	err = json.Unmarshal(b, &ks)
	if err != nil {
		return nil, fmt.Errorf("keystore cannot be parsed | reason %v", err)
	}

	if ks.Cipher == nil {
		return nil, errors.New("cipher cannot be nil")
	}

	var decryptionKey []byte
	kdfParams := ks.KDF.Params
	salt, err := misc.DecodeHex(kdfParams.Salt)
	if err != nil {
		return nil, fmt.Errorf("KDF salt is invalid | reason %v", err)
	}
	switch ks.KDF.Function {
	case "custom":
		decryptionKey, err = passwordToDecryptionKey(passphrase, salt)
	default:
		return nil, fmt.Errorf("invalid KDF %s", ks.KDF.Function)
	}
	if err != nil {
		return nil, errors.New("invalid KDF param")
	}

	if len(decryptionKey) < 32 {
		return nil, fmt.Errorf("decryption key size is less than 32 bytes | current size %d", len(decryptionKey))
	}
	cipherMsg, err := misc.DecodeHex(ks.Cipher.Message)
	if err != nil {
		return nil, errors.New("invalid cipher message")
	}

	decipheredMessage := make([]byte, len(cipherMsg))
	switch ks.Cipher.Function {
	case "aes-256-gcm":
		aesCipher, err := aes.NewCipher(decryptionKey)
		if err != nil {
			return nil, err
		}
		iv, err := misc.DecodeHex(ks.Cipher.Params.IV)
		if err != nil {
			return nil, fmt.Errorf("invalid aes IV | reason %v", err.Error())
		}
		aesgcm, err := cipher.NewGCM(aesCipher)
		if err != nil {
			return nil, err
		}
		if _, err := aesgcm.Open(decipheredMessage, iv, cipherMsg, nil); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported cipher %s", ks.Cipher.Function)
	}

	return decipheredMessage, nil
}
