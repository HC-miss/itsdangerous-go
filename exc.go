package itsdangerous

type BadData struct {
	Message string
}

func (b *BadData) Error() string {
	return b.Message
}

type BadTimeSignature struct {
	Message string
}

func (b *BadTimeSignature) Error() string {
	return b.Message
}

type SignatureExpired struct {
	Message string
}

func (b *SignatureExpired) Error() string {
	return b.Message
}
