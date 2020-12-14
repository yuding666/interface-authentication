package cos

import (
	"crypto/hmac"
	"crypto/sha1"
)

func HmacSHA1(key string, data string) []byte {
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(data))
	return mac.Sum(nil)
}
