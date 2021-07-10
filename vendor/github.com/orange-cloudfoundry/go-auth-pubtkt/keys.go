package pubtkt

// from crypto ssh golang
//
//
// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"math/big"
	"strings"
)

// These constants represent the algorithm names for key types supported by this
// package.
const (
	KeyAlgoRSA      = "ssh-rsa"
	KeyAlgoDSA      = "ssh-dss"
	KeyAlgoECDSA256 = "ecdsa-sha2-nistp256"
	KeyAlgoECDSA384 = "ecdsa-sha2-nistp384"
	KeyAlgoECDSA521 = "ecdsa-sha2-nistp521"
	KeyAlgoED25519  = "ssh-ed25519"
)

// These constants represent non-default signature algorithms that are supported
// as algorithm parameters to AlgorithmSigner.SignWithAlgorithm methods. See
// [PROTOCOL.agent] section 4.5.1 and
// https://tools.ietf.org/html/draft-ietf-curdle-rsa-sha2-10
const (
	SigAlgoRSA        = "ssh-rsa"
	SigAlgoRSASHA2256 = "rsa-sha2-256"
	SigAlgoRSASHA2512 = "rsa-sha2-512"
)

// parseAuthorizedKey parses a public key in OpenSSH authorized_keys format
// (see sshd(8) manual page) once the options and key type fields have been
// removed.
func parseAuthorizedKey(in []byte) (out PublicKey, comment string, err error) {
	in = bytes.TrimSpace(in)

	i := bytes.IndexAny(in, " \t")
	if i == -1 {
		i = len(in)
	}
	base64Key := in[:i]

	key := make([]byte, base64.StdEncoding.DecodedLen(len(base64Key)))
	n, err := base64.StdEncoding.Decode(key, base64Key)
	if err != nil {
		return nil, "", err
	}
	key = key[:n]
	out, err = ssh.ParsePublicKey(key)
	if err != nil {
		return nil, "", err
	}
	comment = string(bytes.TrimSpace(in[i:]))
	return out, comment, nil
}

// ParseAuthorizedKeys parses a public key from an authorized_keys
// file used in OpenSSH according to the sshd(8) manual page.
func ParseAuthorizedKey(in []byte) (out PublicKey, comment string, options []string, rest []byte, err error) {
	for len(in) > 0 {
		end := bytes.IndexByte(in, '\n')
		if end != -1 {
			rest = in[end+1:]
			in = in[:end]
		} else {
			rest = nil
		}

		end = bytes.IndexByte(in, '\r')
		if end != -1 {
			in = in[:end]
		}

		in = bytes.TrimSpace(in)
		if len(in) == 0 || in[0] == '#' {
			in = rest
			continue
		}

		i := bytes.IndexAny(in, " \t")
		if i == -1 {
			in = rest
			continue
		}

		if out, comment, err = parseAuthorizedKey(in[i:]); err == nil {
			return out, comment, options, rest, nil
		}

		// No key type recognised. Maybe there's an options field at
		// the beginning.
		var b byte
		inQuote := false
		var candidateOptions []string
		optionStart := 0
		for i, b = range in {
			isEnd := !inQuote && (b == ' ' || b == '\t')
			if (b == ',' && !inQuote) || isEnd {
				if i-optionStart > 0 {
					candidateOptions = append(candidateOptions, string(in[optionStart:i]))
				}
				optionStart = i + 1
			}
			if isEnd {
				break
			}
			if b == '"' && (i == 0 || (i > 0 && in[i-1] != '\\')) {
				inQuote = !inQuote
			}
		}
		for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
			i++
		}
		if i == len(in) {
			// Invalid line: unmatched quote
			in = rest
			continue
		}

		in = in[i:]
		i = bytes.IndexAny(in, " \t")
		if i == -1 {
			in = rest
			continue
		}

		if out, comment, err = parseAuthorizedKey(in[i:]); err == nil {
			options = candidateOptions
			return out, comment, options, rest, nil
		}

		in = rest
		continue
	}

	return nil, "", nil, nil, errors.New("ssh: no key found")
}

// MarshalAuthorizedKey serializes key for inclusion in an OpenSSH
// authorized_keys file. The return value ends with newline.
func MarshalAuthorizedKey(key PublicKey) []byte {
	b := &bytes.Buffer{}
	b.WriteString(key.Type())
	b.WriteByte(' ')
	e := base64.NewEncoder(base64.StdEncoding, b)
	e.Write(key.Marshal())
	e.Close()
	b.WriteByte('\n')
	return b.Bytes()
}

// PublicKey is an abstraction of different types of public keys.
type PublicKey interface {
	// Type returns the key's type, e.g. "ssh-rsa".
	Type() string

	// Marshal returns the serialized key data in SSH wire format,
	// with the name prefix. To unmarshal the returned data, use
	// the ParsePublicKey function.
	Marshal() []byte

	// Verify that sig is a signature on the given data using this
	// key. This function will hash the data appropriately first.
	Verify(data []byte, sig *ssh.Signature) error
}

// A Signer can create signatures that verify against a public key.
type Signer interface {
	// PublicKey returns an associated PublicKey instance.
	PublicKey() PublicKey

	// Sign returns raw signature for the given data. This method
	// will apply the hash specified for the keytype to the data.
	Sign(rand io.Reader, data []byte) (*ssh.Signature, error)
}

// A AlgorithmSigner is a Signer that also supports specifying a specific
// algorithm to use for signing.
type AlgorithmSigner interface {
	Signer

	// SignWithAlgorithm is like Signer.Sign, but allows specification of a
	// non-default signing algorithm. See the SigAlgo* constants in this
	// package for signature algorithms supported by this package. Callers may
	// pass an empty string for the algorithm in which case the AlgorithmSigner
	// will use its default algorithm.
	SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error)
}

type rsaPublicKey rsa.PublicKey

func (r *rsaPublicKey) Type() string {
	return "ssh-rsa"
}

func (r *rsaPublicKey) Marshal() []byte {
	e := new(big.Int).SetInt64(int64(r.E))
	// RSA publickey struct layout should match the struct used by
	// parseRSACert in the x/crypto/ssh/agent package.
	wirekey := struct {
		Name string
		E    *big.Int
		N    *big.Int
	}{
		KeyAlgoRSA,
		e,
		r.N,
	}
	return ssh.Marshal(&wirekey)
}

func (r *rsaPublicKey) Verify(data []byte, sig *ssh.Signature) error {
	var hash crypto.Hash
	switch sig.Format {
	case SigAlgoRSA:
		hash = crypto.SHA1
	case SigAlgoRSASHA2256:
		hash = crypto.SHA256
	case SigAlgoRSASHA2512:
		hash = crypto.SHA512
	default:
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, r.Type())
	}
	h := hash.New()
	h.Write(data)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15((*rsa.PublicKey)(r), hash, digest, sig.Blob)
}

func (r *rsaPublicKey) CryptoPublicKey() crypto.PublicKey {
	return (*rsa.PublicKey)(r)
}

type dsaPublicKey dsa.PublicKey

func (k *dsaPublicKey) Type() string {
	return "ssh-dss"
}

func checkDSAParams(param *dsa.Parameters) error {
	return nil
}

func (k *dsaPublicKey) Marshal() []byte {
	// DSA publickey struct layout should match the struct used by
	// parseDSACert in the x/crypto/ssh/agent package.
	w := struct {
		Name       string
		P, Q, G, Y *big.Int
	}{
		k.Type(),
		k.P,
		k.Q,
		k.G,
		k.Y,
	}

	return ssh.Marshal(&w)
}

func (k *dsaPublicKey) Verify(data []byte, sig *ssh.Signature) error {
	if sig.Format != k.Type() {
		return fmt.Errorf("ssh: signature type %s for key type %s", sig.Format, k.Type())
	}
	h := crypto.SHA1.New()
	h.Write(data)
	digest := h.Sum(nil)

	// Per RFC 4253, section 6.6,
	// The value for 'dss_signature_blob' is encoded as a string containing
	// r, followed by s (which are 160-bit integers, without lengths or
	// padding, unsigned, and in network byte order).
	// For DSS purposes, sig.Blob should be exactly 40 bytes in length.
	if len(sig.Blob) != 40 {
		return errors.New("ssh: DSA signature parse error")
	}
	r := new(big.Int).SetBytes(sig.Blob[:20])
	s := new(big.Int).SetBytes(sig.Blob[20:])
	if dsa.Verify((*dsa.PublicKey)(k), digest, r, s) {
		return nil
	}
	return errors.New("ssh: signature did not verify")
}

func (k *dsaPublicKey) CryptoPublicKey() crypto.PublicKey {
	return (*dsa.PublicKey)(k)
}

type dsaPrivateKey struct {
	*dsa.PrivateKey
}

func (k *dsaPrivateKey) PublicKey() PublicKey {
	return (*dsaPublicKey)(&k.PrivateKey.PublicKey)
}

func (k *dsaPrivateKey) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return k.SignWithAlgorithm(rand, data, "")
}

func (k *dsaPrivateKey) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if algorithm != "" && algorithm != k.PublicKey().Type() {
		return nil, fmt.Errorf("ssh: unsupported signature algorithm %s", algorithm)
	}

	h := crypto.SHA1.New()
	h.Write(data)
	digest := h.Sum(nil)
	r, s, err := dsa.Sign(rand, k.PrivateKey, digest)
	if err != nil {
		return nil, err
	}

	sig, err := asn1.Marshal(struct {
		R, S *big.Int
	}{r, s})
	if err != nil {
		return nil, err
	}
	return &ssh.Signature{
		Format: k.PublicKey().Type(),
		Blob:   sig,
	}, nil
}

// NewSignerFromKey takes an *rsa.PrivateKey, *dsa.PrivateKey,
// *ecdsa.PrivateKey or any other crypto.Signer and returns a
// corresponding Signer instance. ECDSA keys must use P-256, P-384 or
// P-521. DSA keys must use parameter size L1024N160.
func NewSignerFromKey(key interface{}) (Signer, error) {
	switch key := key.(type) {
	case crypto.Signer:
		return NewSignerFromSigner(key)
	case *dsa.PrivateKey:
		return newDSAPrivateKey(key)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", key)
	}
}

func newDSAPrivateKey(key *dsa.PrivateKey) (Signer, error) {
	if err := checkDSAParams(&key.PublicKey.Parameters); err != nil {
		return nil, err
	}

	return &dsaPrivateKey{key}, nil
}

type wrappedSigner struct {
	signer crypto.Signer
	pubKey PublicKey
}

func NewPublicKey(key interface{}) (PublicKey, error) {
	switch key := key.(type) {
	case *rsa.PublicKey:
		return (*rsaPublicKey)(key), nil
	case *dsa.PublicKey:
		return (*dsaPublicKey)(key), nil
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", key)
	}
}

// NewSignerFromSigner takes any crypto.Signer implementation and
// returns a corresponding Signer interface. This can be used, for
// example, with keys kept in hardware modules.
func NewSignerFromSigner(signer crypto.Signer) (Signer, error) {
	pubKey, err := NewPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}

	return &wrappedSigner{signer, pubKey}, nil
}

func (s *wrappedSigner) PublicKey() PublicKey {
	return s.pubKey
}

func (s *wrappedSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, "")
}

func (s *wrappedSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	var hashFunc crypto.Hash

	if _, ok := s.pubKey.(*rsaPublicKey); ok {
		// RSA keys support a few hash functions determined by the requested signature algorithm
		switch algorithm {
		case "", SigAlgoRSA:
			algorithm = SigAlgoRSA
			hashFunc = crypto.SHA1
		case SigAlgoRSASHA2256:
			hashFunc = crypto.SHA256
		case SigAlgoRSASHA2512:
			hashFunc = crypto.SHA512
		default:
			return nil, fmt.Errorf("ssh: unsupported signature algorithm %s", algorithm)
		}
	} else {
		// The only supported algorithm for all other key types is the same as the type of the key
		if algorithm == "" {
			algorithm = s.pubKey.Type()
		} else if algorithm != s.pubKey.Type() {
			return nil, fmt.Errorf("ssh: unsupported signature algorithm %s", algorithm)
		}

		switch key := s.pubKey.(type) {
		case *dsaPublicKey:
			hashFunc = crypto.SHA1
		default:
			return nil, fmt.Errorf("ssh: unsupported key type %T", key)
		}
	}

	var digest []byte
	if hashFunc != 0 {
		h := hashFunc.New()
		h.Write(data)
		digest = h.Sum(nil)
	} else {
		digest = data
	}

	signature, err := s.signer.Sign(rand, digest, hashFunc)
	if err != nil {
		return nil, err
	}

	// crypto.Signer.Sign is expected to return an ASN.1-encoded signature
	// for ECDSA and DSA, but that's not the encoding expected by SSH, so
	// re-encode.
	switch s.pubKey.(type) {
	case *dsaPublicKey:
		type asn1Signature struct {
			R, S *big.Int
		}
		asn1Sig := new(asn1Signature)
		_, err := asn1.Unmarshal(signature, asn1Sig)
		if err != nil {
			return nil, err
		}

		switch s.pubKey.(type) {

		case *dsaPublicKey:
			signature = make([]byte, 40)
			r := asn1Sig.R.Bytes()
			s := asn1Sig.S.Bytes()
			copy(signature[20-len(r):20], r)
			copy(signature[40-len(s):40], s)
		}
	}

	return &ssh.Signature{
		Format: algorithm,
		Blob:   signature,
	}, nil
}

// ParsePrivateKey returns a Signer from a PEM encoded private key. It supports
// the same keys as ParseRawPrivateKey.
func ParsePrivateKey(pemBytes []byte) (Signer, error) {
	key, err := ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	return NewSignerFromKey(key)
}

// ParsePrivateKeyWithPassphrase returns a Signer from a PEM encoded private
// key and passphrase. It supports the same keys as
// ParseRawPrivateKeyWithPassphrase.
func ParsePrivateKeyWithPassphrase(pemBytes, passPhrase []byte) (Signer, error) {
	key, err := ParseRawPrivateKeyWithPassphrase(pemBytes, passPhrase)
	if err != nil {
		return nil, err
	}

	return NewSignerFromKey(key)
}

// encryptedBlock tells whether a private key is
// encrypted by examining its Proc-Type header
// for a mention of ENCRYPTED
// according to RFC 1421 Section 4.6.1.1.
func encryptedBlock(block *pem.Block) bool {
	return strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED")
}

// ParseRawPrivateKey returns a private key from a PEM encoded private key. It
// supports RSA (PKCS#1), PKCS#8, DSA (OpenSSL), and ECDSA private keys.
func ParseRawPrivateKey(pemBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}

	if encryptedBlock(block) {
		return nil, errors.New("ssh: cannot decode encrypted private keys")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	// RFC5208 - https://tools.ietf.org/html/rfc5208
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "DSA PRIVATE KEY":
		return ParseDSAPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

// ParseRawPrivateKeyWithPassphrase returns a private key decrypted with
// passphrase from a PEM encoded private key. If wrong passphrase, return
// x509.IncorrectPasswordError.
func ParseRawPrivateKeyWithPassphrase(pemBytes, passPhrase []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ssh: no key found")
	}
	buf := block.Bytes

	if encryptedBlock(block) {
		if x509.IsEncryptedPEMBlock(block) {
			var err error
			buf, err = x509.DecryptPEMBlock(block, passPhrase)
			if err != nil {
				if err == x509.IncorrectPasswordError {
					return nil, err
				}
				return nil, fmt.Errorf("ssh: cannot decode encrypted private keys: %v", err)
			}
		}
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(buf)
	case "DSA PRIVATE KEY":
		return ParseDSAPrivateKey(buf)
	default:
		return nil, fmt.Errorf("ssh: unsupported key type %q", block.Type)
	}
}

// ParseDSAPrivateKey returns a DSA private key from its ASN.1 DER encoding, as
// specified by the OpenSSL DSA man page.
func ParseDSAPrivateKey(der []byte) (*dsa.PrivateKey, error) {
	var k struct {
		Version int
		P       *big.Int
		Q       *big.Int
		G       *big.Int
		Pub     *big.Int
		Priv    *big.Int
	}
	rest, err := asn1.Unmarshal(der, &k)
	if err != nil {
		return nil, errors.New("ssh: failed to parse DSA key: " + err.Error())
	}
	if len(rest) > 0 {
		return nil, errors.New("ssh: garbage after DSA key")
	}

	return &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: k.P,
				Q: k.Q,
				G: k.G,
			},
			Y: k.Pub,
		},
		X: k.Priv,
	}, nil
}

// FingerprintLegacyMD5 returns the user presentation of the key's
// fingerprint as described by RFC 4716 section 4.
func FingerprintLegacyMD5(pubKey PublicKey) string {
	md5sum := md5.Sum(pubKey.Marshal())
	hexarray := make([]string, len(md5sum))
	for i, c := range md5sum {
		hexarray[i] = hex.EncodeToString([]byte{c})
	}
	return strings.Join(hexarray, ":")
}

// FingerprintSHA256 returns the user presentation of the key's
// fingerprint as unpadded base64 encoded sha256 hash.
// This format was introduced from OpenSSH 6.8.
// https://www.openssh.com/txt/release-6.8
// https://tools.ietf.org/html/rfc4648#section-3.2 (unpadded base64 encoding)
func FingerprintSHA256(pubKey PublicKey) string {
	sha256sum := sha256.Sum256(pubKey.Marshal())
	hash := base64.RawStdEncoding.EncodeToString(sha256sum[:])
	return "SHA256:" + hash
}
