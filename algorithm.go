package itsdangerous

import (
	"crypto/hmac"
	"crypto/sha1"
	"hash"
)

type SigningAlgorithm interface {
	GetSignature(key, value []byte) []byte
	VerifySignature(key, value, sig []byte) bool
}

type NoneAlgorithm struct{}

func (alg *NoneAlgorithm) GetSignature(_, _ []byte) []byte {
	return []byte{'b'}
}

func (alg *NoneAlgorithm) VerifySignature(key, value, sig []byte) bool {
	return hmac.Equal(alg.GetSignature(key, value), sig)
}

type HMACAlgorithm struct {
	DigestMethod func() hash.Hash
}

func (alg *HMACAlgorithm) GetSignature(key, value []byte) []byte {
	if alg.DigestMethod == nil {
		alg.DigestMethod = sha1.New
	}

	mac := hmac.New(alg.DigestMethod, key)
	mac.Write(value)
	return mac.Sum(nil)
}

func (alg *HMACAlgorithm) VerifySignature(key, value, sig []byte) bool {
	return hmac.Equal(alg.GetSignature(key, value), sig)
}
