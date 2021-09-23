package signer

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash"
	"itsdangerous-go"
	"itsdangerous-go/encoding"
	"time"
)

// Works like the regular Signer but also records the time of the signing and can be used to
// expire signatures. The Unsign method can raise itsdangerous-go.BadTimeSignature if the unsigning failed
// because the signature is expired
type TimestampSigner struct {
	Signer
}

func NewTimestampSigner(
	secretKey, salt, sep []byte,
	digestMethod func() hash.Hash,
	keyDerivation string,
	algorithm itsdangerous.SigningAlgorithm,
) *TimestampSigner {
	signer := NewSigner(secretKey, salt, sep, digestMethod, keyDerivation, algorithm)
	return &TimestampSigner{*signer}
}

func DefaultTimestampSigner(
	secretKey, salt, sep []byte,
) *TimestampSigner {
	return NewTimestampSigner(secretKey, salt, sep, nil, "", nil)
}

func (signer *TimestampSigner) GetTimestamp() int64 {
	return time.Now().Unix()
}

func (signer *TimestampSigner) TimestampToTime(ts int64) time.Time {
	return time.Unix(ts, 0)
}

// Signs the given slice and also attaches time information.
func (signer *TimestampSigner) Sign(value []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.BigEndian, uint64(signer.GetTimestamp()))
	if err != nil {
		return nil, err
	}

	timestamp := encoding.Base64Encode(bytes.TrimLeft(buf.Bytes(), "\x00"))
	value = encoding.BytesCombine(value, signer.sep, timestamp)
	return encoding.BytesCombine(value, signer.sep, signer.GetSignature(value)), nil
}

// Works like the regular Signer.Unsign but can also validate the time.
func (signer *TimestampSigner) GetSignedTimestamp(signedValue []byte) (time.Time, error) {
	var signedTime time.Time

	unSignResult, err := signer.Signer.Unsign(signedValue)

	if err != nil {
		return signedTime, err
	}

	if !bytes.Contains(unSignResult, signer.sep) {
		return signedTime, &itsdangerous.BadTimeSignature{Message: "timestamp missing"}
	}

	lastIndex := bytes.LastIndex(unSignResult, signer.sep)

	tsBytes := unSignResult[lastIndex+len(signer.sep):]

	sig, err := encoding.Base64Decode(tsBytes)
	if err != nil {
		return signedTime, err
	}

	var (
		timestamp uint64
		padLen    int
	)

	if l := len(sig) % 8; l > 0 {
		padLen = 8 - l
	} else {
		padLen = 1
	}

	buf := bytes.NewReader(encoding.BytesCombine(bytes.Repeat([]byte("\x00"), padLen), sig))

	if err = binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
		return signedTime, &itsdangerous.BadTimeSignature{Message: "Malformed timestamp"}
	}

	signedTime = signer.TimestampToTime(int64(timestamp))
	return signedTime, nil
}

func (signer *TimestampSigner) Unsign(signedValue []byte, maxAge int64) ([]byte, error) {
	unSignResult, err := signer.Signer.Unsign(signedValue)

	if err != nil {
		return nil, err
	}

	if !bytes.Contains(unSignResult, signer.sep) {
		return nil, &itsdangerous.BadTimeSignature{Message: "timestamp missing"}
	}

	lastIndex := bytes.LastIndex(unSignResult, signer.sep)

	tsBytes := unSignResult[lastIndex+len(signer.sep):]
	value := unSignResult[:lastIndex]

	fmt.Printf("signedValue: %s\n", signedValue)
	sig, err := encoding.Base64Decode(tsBytes)
	fmt.Printf("signedValue: %s\n", signedValue)

	if err != nil {
		return nil, err
	}

	var (
		timestamp uint64
		padLen    int
	)

	if l := len(sig) % 8; l > 0 {
		padLen = 8 - l
	} else {
		padLen = 1
	}

	buf := bytes.NewReader(encoding.BytesCombine(bytes.Repeat([]byte("\x00"), padLen), sig))

	if err = binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
		return nil, &itsdangerous.BadTimeSignature{Message: "Malformed timestamp"}
	}

	if maxAge > 0 {
		age := signer.GetTimestamp() - int64(timestamp)
		if age > maxAge {
			return nil, &itsdangerous.SignatureExpired{Message: fmt.Sprintf("Signature age %d > %d seconds", age, maxAge)}
		}

		if age < 0 {
			return nil, &itsdangerous.SignatureExpired{Message: fmt.Sprintf("Signature age %d < 0 seconds", age)}
		}
	}
	return value, nil
}

func (signer *TimestampSigner) Validate(signedValue []byte, maxAge int64) bool {
	_, err := signer.Unsign(signedValue, maxAge)
	if err != nil {
		return false
	}
	return true
}
