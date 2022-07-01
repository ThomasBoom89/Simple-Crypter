package simple_crypter

import (
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
