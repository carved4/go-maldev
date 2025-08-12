/*
decrypt is to be used with a payload extracted from a file created via generator.go
see cmd/main.go for usage pattern :3
*/

package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

func Decrypt(pebytes []byte) ([]byte, error) {
	keySize := 32
	if len(pebytes) < keySize {
		return nil, fmt.Errorf("data too short to contain key")
	}

	key := pebytes[len(pebytes)-keySize:]
	encryptedData := pebytes[:len(pebytes)-keySize]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := aesGCM.NonceSize()
	if len(encryptedData) < nonceSize+aesGCM.Overhead() {
		return nil, fmt.Errorf("encrypted data too short for nonce and tag")
	}

	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

