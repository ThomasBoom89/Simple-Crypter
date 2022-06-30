package simple_crypter

import (
	"encoding/base64"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	cases := []struct {
		password string
		text     string
	}{
		{"", "dies ist super geheim"},
		{"ßkjdfl*&3er0Ä", "ein geheimes geheimnis"},
		{"sfjl öißdfj9", "D8ZBUH37Kzi2dgcdZI3tUq/W1Iqzo4="},
		{"ßdlafjklßdjfkljsdklfjkßjdfio2u3879u8f2wjfwe89jf9w", ""},
	}

	for _, c := range cases {
		crypter := New()
		ciphertext, err := crypter.Encrypt(c.password, c.text)
		if err != nil {
			t.Error("should not throw err: ", err)
		}

		text, err := crypter.Decrypt(c.password, ciphertext)
		if text != c.text {
			t.Error("key should be equal: ", text, c.text)
		}
	}
}

func TestGenerateKeyFromPassword(t *testing.T) {
	cases := []struct {
		password    string
		expectedKey string
	}{
		{"", "0YYpWPDP6PuvPBkH8boAt9cQsrDpElExheZpmmqMfdY="},
		{"ßkjdfl*&3er0Ä", "ym2QYwnRBslS96ctEsv0/y9hhCnvlyX9eVzIWHdrcYo="},
		{"sfjl öißdfj9", "D8ZBUH37Kzi2r2Wf3GtrwqxG3dgcdZI3tUq/W1Iqzo4="},
		{"ßdlafjklßdjfkljsdklfjkßjdfio2u3879u8f2wjfwe89jf9w", "AtRpc+S2J05yafzR8zPYadOyheWREoWiT76JBNpkd2U="},
	}

	for _, c := range cases {
		crypter := New()
		key, err := crypter.generateKeyFromPassword(c.password)
		if err != nil {
			t.Error("should not throw err: ", err)
		}
		encodedKey := base64.StdEncoding.EncodeToString(key)
		if encodedKey != c.expectedKey {
			t.Error("key should be equal: ", encodedKey, c.expectedKey)
		}

		if len(key) != 32 {
			t.Error("key should have a length of 32 byte: ", encodedKey)
		}
	}
}
