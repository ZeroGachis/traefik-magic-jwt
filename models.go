package traefik_magic_jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

type JwtHeader struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Cty  string   `json:"cty"`
	Crit []string `json:"crit"`
}
type tokenPayLoad struct {
	Iat json.Number `json:"iat"`
	Exp json.Number `json:"exp"`
}
type JWT struct {
	Plaintext  []byte
	Signature  []byte
	Header     JwtHeader
	Payload    tokenPayLoad
	RawPayload []byte
}

var supportedHeaderNames = map[string]struct{}{"alg": {}, "kid": {}, "typ": {}, "cty": {}, "crit": {}}

type tokenVerifyFunction func(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error
type tokenVerifyAsymmetricFunction func(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error

// jwtAlgorithm describes a JWS 'alg' value
type tokenAlgorithm struct {
	hash   crypto.Hash
	verify tokenVerifyFunction
}

// tokenAlgorithms is the known JWT algorithms
var (
	tokenAlgorithms = map[string]tokenAlgorithm{
		"RS256": {crypto.SHA256, verifyAsymmetric(verifyRSAPKCS)},
		"HS256": {crypto.SHA256, verifyHMAC},
	}
	noTokenError      = &RequestError{StatusCode: http.StatusUnauthorized, Message: "No Token Detect"}
	badTokenError     = &RequestError{StatusCode: http.StatusBadRequest, Message: "Invalid Token"}
	verifyTokenError  = &RequestError{StatusCode: http.StatusBadRequest, Message: "Verify Error"}
	expiredTokenError = &RequestError{StatusCode: http.StatusUnavailableForLegalReasons, Message: "Expired Token"}
)

func verifyHMAC(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error {
	macKey, ok := key.([]byte)
	if !ok {
		return fmt.Errorf("incorrect symmetric key type")
	}
	mac := hmac.New(hash.New, macKey)
	if _, err := mac.Write([]byte(payload)); err != nil {
		return err
	}
	if !hmac.Equal(signature, mac.Sum([]byte{})) {
		return errors.New("signature not verified")
	}
	return nil
}
func verifyAsymmetric(verify tokenVerifyAsymmetricFunction) tokenVerifyFunction {
	return func(key interface{}, hash crypto.Hash, payload []byte, signature []byte) error {
		h := hash.New()
		_, err := h.Write(payload)
		if err != nil {
			return err
		}
		return verify(key, hash, h.Sum([]byte{}), signature)
	}
}

func verifyRSAPKCS(key interface{}, hash crypto.Hash, digest []byte, signature []byte) error {
	publicKeyRsa := key.(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(publicKeyRsa, hash, digest, signature); err != nil {
		return fmt.Errorf("token verification failed (RSAPKCS)")
	}
	return nil
}

type WhiteUrl struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Type   string `json:"type,omitempty"`
}

type RequestError struct {
	StatusCode int
	Message    string
}

func httpError(w http.ResponseWriter, e string, code int) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	fmt.Fprint(w, e)
}
