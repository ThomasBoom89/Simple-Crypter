package simple_crypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"golang.org/x/crypto/scrypt"
	"io"
)

type Crypter struct {
}

func New() *Crypter {
	return &Crypter{}
}

func (C *Crypter) Encrypt(secret, text string) (string, error) {
	key, err := C.generateKeyFromPassword(secret)
	if err != nil {
		return "", err
	}

	aesgcm, err := C.getAesGcmFromKey(key)
	if err != nil {
		return "", err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesgcm.Seal(nonce, nonce, []byte(text), nil)

	return string(ciphertext), nil
}

func (C *Crypter) Decrypt(secret, text string) (string, error) {
	key, err := C.generateKeyFromPassword(secret)
	if err != nil {
		return "", err
	}

	aesgcm, err := C.getAesGcmFromKey(key)
	if err != nil {
		return "", err
	}

	enc := []byte(text)
	nonceSize := aesgcm.NonceSize()
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func (C *Crypter) getAesGcmFromKey(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm, nil
}

func (C *Crypter) generateKeyFromPassword(password string) ([]byte, error) {
	key, err := scrypt.Key([]byte(password), []byte("supersalty"), 32768, 16, 4, 32)
	if err != nil {
		return nil, err
	}

	return key, nil
}
