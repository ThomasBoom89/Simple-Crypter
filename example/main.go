package main

import simple_crypter "github.com/ThomasBoom89/simple-crypter"

func main() {
	crypter := simple_crypter.New()
	secret := "superGeheimesPassword2&8*"
	ciphertext, err := crypter.Encrypt(secret, "geheimerText")
	if err != nil {
		return
	}
	_, err = crypter.Decrypt(secret, ciphertext)
	if err != nil {
		return
	}
}
