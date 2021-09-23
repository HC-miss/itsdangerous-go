package signer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"hash"
	"itsdangerous"
	"itsdangerous/encoding"
)

var (
	defaultKeyDerivation = "django-concat"
	base64Alphabet       = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_=")
)

type Signer struct {
	secretKey     []byte // 暂时不支持密钥轮换
	salt          []byte
	sep           []byte
	keyDerivation string
	digestMethod  func() hash.Hash
	algorithm     itsdangerous.SigningAlgorithm
}

func DefaultSigner(secretKey, salt, sep []byte) *Signer {
	return NewSigner(secretKey, salt, sep, nil, "", nil)
}

func NewSigner(
	secretKey, salt, sep []byte,
	digestMethod func() hash.Hash,
	keyDerivation string,
	algorithm itsdangerous.SigningAlgorithm,
) *Signer {
	if sep == nil {
		sep = []byte{'.'}
	}

	if bytes.Contains(sep, base64Alphabet) {
		panic("The given separator cannot be used because " +
			"it may be contained in the signature itself. ASCII letters, digits," +
			" and '-_=' must not be used.",
		)
	}

	if salt == nil {
		salt = []byte("itsdangerous.Signer")
	}

	if keyDerivation == "" {
		keyDerivation = defaultKeyDerivation
	}

	if digestMethod == nil {
		digestMethod = sha1.New
	}

	if algorithm == nil {
		algorithm = &itsdangerous.HMACAlgorithm{DigestMethod: digestMethod}
	}

	return &Signer{
		secretKey:     secretKey,
		sep:           sep,
		salt:          salt,
		keyDerivation: keyDerivation,
		digestMethod:  digestMethod,
		algorithm:     algorithm,
	}
}

func (signer *Signer) DeriveKey(secretKey []byte) []byte {
	if secretKey == nil {
		secretKey = signer.secretKey
	}

	switch signer.keyDerivation {
	case "concat":
		concatKey := make([]byte, 0, len(signer.salt)+len(secretKey))
		concatKey = append(concatKey, signer.salt...)
		concatKey = append(concatKey, secretKey...)

		digest := signer.digestMethod()
		digest.Write(concatKey)
		return digest.Sum(nil)
	case "django-concat":
		concatKey := make([]byte, 0, len(signer.salt)+len(secretKey))
		concatKey = append(concatKey, signer.salt...)
		concatKey = append(concatKey, []byte("signer")...)
		concatKey = append(concatKey, secretKey...)

		digest := signer.digestMethod()
		digest.Write(concatKey)
		return digest.Sum(nil)
	case "hmac":
		mac := hmac.New(signer.digestMethod, secretKey)
		mac.Write(signer.salt)
		return mac.Sum(nil)
	case "none":
		return secretKey
	default:
		panic("Unknown key derivation method")
	}
}

func (signer *Signer) GetSignature(value []byte) []byte {
	key := signer.DeriveKey(nil)
	sig := signer.algorithm.GetSignature(key, value)
	return encoding.Base64Encode(sig)
}

func (signer *Signer) Sign(value []byte) []byte {
	signature := signer.GetSignature(value)
	return encoding.BytesCombine(value, signer.sep, signature)
}

func (signer *Signer) VerifySignature(value, sig []byte) bool {
	sig, err := encoding.Base64Decode(sig)
	if err != nil {
		return false
	}
	key := signer.DeriveKey(signer.secretKey)
	return signer.algorithm.VerifySignature(key, value, sig)
}

func (signer *Signer) Unsign(signedValue []byte) ([]byte, error) {
	if !bytes.Contains(signedValue, signer.sep) {
		return nil, &itsdangerous.BadData{Message: fmt.Sprintf("No %s found in value", signer.sep)}
	}

	lastIndex := bytes.LastIndex(signedValue, signer.sep)

	sig := signedValue[lastIndex+len(signer.sep):]
	value := signedValue[:lastIndex]

	if signer.VerifySignature(value, sig) {
		return value, nil
	}
	return nil, &itsdangerous.BadData{Message: fmt.Sprintf("Signature %s does not match", sig)}
}

func (signer *Signer) Validate(signedValue []byte) bool {
	_, err := signer.Unsign(signedValue)
	if err != nil {
		return false
	}
	return true
}
