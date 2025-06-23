package keystorev1

type Encryptor struct {
	cipher string
}

type paramsKDF struct {
	Salt string `json:"salt"`
}

type _kdf struct {
	Function string     `json:"function"`
	Params   *paramsKDF `json:"params"`
	Message  string     `json:"message"`
}

type paramsCipher struct {
	IV string `json:"iv,omitempty"`
}

type _cipher struct {
	Function string        `json:"function"`
	Params   *paramsCipher `json:"params"`
	Message  string        `json:"message"`
}

type keystoreV1 struct {
	KDF    *_kdf    `json:"kdf"`
	Cipher *_cipher `json:"cipher"`
}

const (
	name    = "keystore"
	version = 1
)

type options struct {
	cipher string
}

type Option interface {
	apply(*options)
}

type optionFunc func(*options)

func (f optionFunc) apply(o *options) {
	f(o)
}

func WithCipher(cipher string) Option {
	return optionFunc(func(o *options) {
		o.cipher = cipher
	})
}

func New(opts ...Option) *Encryptor {
	options := options{
		cipher: "custom",
	}
	for _, o := range opts {
		o.apply(&options)
	}

	return &Encryptor{
		cipher: options.cipher,
	}
}

func (e *Encryptor) Name() string {
	return name
}

func (e *Encryptor) Version() uint {
	return version
}
