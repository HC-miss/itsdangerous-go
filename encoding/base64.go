package encoding

import (
	"bytes"
	"encoding/base64"
	"itsdangerous-go"
)

func BytesCombine(valueBytes ...[]byte) []byte {
	return bytes.Join(valueBytes, []byte(""))
}

func Base64Encode(src []byte) []byte {
	dst := make([]byte, base64.URLEncoding.EncodedLen(len(src)))
	base64.URLEncoding.Encode(dst, src)
	dst = bytes.TrimRight(dst, "=")
	return dst
}

func Base64Decode(src []byte) ([]byte, error) {
	var (
		padLen int
		eqChar = []byte{'='}
	)
	if l := len(src) % 4; l > 0 {
		padLen = 4 - l
	} else {
		padLen = 1
	}

	copySrc := BytesCombine(src, bytes.Repeat(eqChar, padLen))
	dst := make([]byte, base64.URLEncoding.DecodedLen(len(copySrc)))

	n, err := base64.URLEncoding.Decode(dst, copySrc)
	if err != nil {
		return nil, &itsdangerous.BadData{Message: "Invalid base64-encoded data"}
	}
	return dst[:n], nil
}
