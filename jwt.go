package traefik_magic_jwt

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type Config struct {
	Key          string               `json:"key"`
	Alg          string               `json:"-"`
	InjectHeader string               `json:"-"`
	Debug        bool                 `json:"debug,omitempty"`
	White        map[string]*WhiteUrl `json:"white,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type JwtPlugin struct {
	next         http.Handler
	rsa          interface{}
	alg          string
	injectHeader string
	debug        bool
	white        map[string]*WhiteUrl
}

func New(context context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	if len(config.Key) == 0 {
		config.Key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuKijNSLvTJqPV+H/MfoR\nI/EkasKIYBTujUTjN5nxrw6q7acJlyq5pzb1MMMQqe/h1ACMmoWJ9dLHJqVMFz+h\nNkx99eWkXDj2agTjnh6VetG6owdC0yYiN2nm5eFsLtj8HBPhKF+5WguLUXoeNhOc\n0zdEfI6UkyLp+xmKVzrs7wXmBVaz0nV69drIYo8RI1+AUzHKJVOuWwykpcH+wk8P\nGvxXGw7CzM2NWAF5B9OUB+InAFApXx8FLZ0jQOAvCJcPZ7So7isxIyCD5RlhbcId\n35ZmzwBuOlskdyswX78yGc46aEAWFDUkMfrXZEy+RGoj0KunXwKKufh+bHYsKmvC\nywIDAQAB\n-----END PUBLIC KEY-----"
	}
	if len(config.Alg) == 0 {
		config.Alg = "RS256"
	}
	if len(config.InjectHeader) == 0 {
		config.InjectHeader = "injectedPayload"
	}
	jwtPlugin := &JwtPlugin{
		next:         next,
		injectHeader: config.InjectHeader,
		debug:        config.Debug,
		alg:          config.Alg,
		white:        config.White,
	}
	if config.Alg == "RS256" {
		if err := jwtPlugin.ParseKeys(config.Key); err != nil {
			return nil, err
		}
	} else if config.Alg == "HS256" {
		jwtPlugin.rsa = []byte(config.Key)
	} else {
		return nil, errors.New("bad alg")
	}
	return jwtPlugin, nil
}

func (jwtPlugin *JwtPlugin) ServeHTTP(rw http.ResponseWriter, request *http.Request) {
	ignoreExpired := false
	logger := log.New(os.Stdout, "jwt: ["+request.RemoteAddr+"]", log.Ldate|log.Ltime)
	if jwtPlugin.white != nil {
		for _, v := range jwtPlugin.white {
			if v.Type == "" {
				v.Type = "full"
			}
			if strings.EqualFold(v.Type, "full") && strings.EqualFold(v.Method, request.Method) && strings.EqualFold(v.URL, request.URL.Path) {
				log.Println("Serve White url")
				jwtPlugin.next.ServeHTTP(rw, request)
				return
			}
			if strings.EqualFold(v.Type, "refresh") && strings.EqualFold(v.Method, request.Method) && strings.EqualFold(v.URL, request.URL.Path) {
				ignoreExpired = true
			}
		}
	}
	if err := jwtPlugin.CheckToken(request, ignoreExpired, logger); err != nil {
		logger.Printf("Error Handle Token %+v\n", err)
		httpError(rw, err.Message, err.StatusCode)
		return
	}
	jwtPlugin.next.ServeHTTP(rw, request)
}
func (jwtPlugin *JwtPlugin) ParseKeys(certificate string) error {
	if block, rest := pem.Decode([]byte(certificate)); block != nil {
		if len(rest) > 0 {
			return fmt.Errorf("extra data after a PEM certificate block")
		}
		if block.Type == "PUBLIC KEY" || block.Type == "RSA PUBLIC KEY" {
			key, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return fmt.Errorf("failed to parse a PEM public key: %v", err)
			}
			jwtPlugin.rsa = key
		}
	}
	return nil
}
func (jwtPlugin *JwtPlugin) CheckToken(request *http.Request, ignorExpired bool, log *log.Logger) *RequestError {
	jwtToken, err := jwtPlugin.ExtractToken(request, log)
	if err != nil {
		return err
	}
	if jwtToken != nil {
		if err = jwtPlugin.VerifyToken(jwtToken, log); err != nil {
			return err
		}
		if !ignorExpired {
			if err = handleTokenTime(jwtToken); err != nil {
				return err
			}
		}
		request.Header.Del("Authorization")
		request.Header.Add(jwtPlugin.injectHeader, string(jwtToken.RawPayload))
	}
	return nil
}
func handleTokenTime(jwt *JWT) *RequestError {
	expiredate, err := jwt.Payload.Exp.Int64()
	if err != nil {
		return expiredTokenError
	}
	if isExpire(expiredate) {
		return expiredTokenError
	}
	return nil
}
func (jwtPlugin *JwtPlugin) ExtractToken(request *http.Request, log *log.Logger) (*JWT, *RequestError) {
	authHeader, ok := request.Header["Authorization"]
	if !ok {
		log.Println("Header Authorization not found")
		return nil, noTokenError
	}
	auth := authHeader[0]
	if !strings.HasPrefix(auth, "Bearer ") {
		log.Printf("No Beadrer token %s\n", auth)
		return nil, noTokenError
	}
	parts := strings.Split(auth[7:], ".")
	if len(parts) != 3 {
		log.Println("Invalid Token format")
		return nil, noTokenError
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		log.Printf("Header: %+v\n", err)
		return nil, badTokenError
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		log.Printf("Payload: %+v\n", err)
		return nil, badTokenError
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		log.Printf("Signature: %+v\n", err)
		return nil, badTokenError
	}
	jwtToken := JWT{
		Plaintext:  []byte(auth[7 : len(parts[0])+len(parts[1])+8]),
		Signature:  signature,
		RawPayload: payload,
	}
	err = json.Unmarshal(header, &jwtToken.Header)
	if err != nil {
		log.Printf("Json Header bad format %+v\n", err)
		return nil, badTokenError
	}
	err = json.Unmarshal(payload, &jwtToken.Payload)
	if err != nil {
		log.Printf("Json Payload bad format %+v\n", err)
		return nil, badTokenError
	}
	return &jwtToken, nil
}

func (jwtPlugin *JwtPlugin) VerifyToken(jwtToken *JWT, log *log.Logger) *RequestError {
	for _, h := range jwtToken.Header.Crit {
		if _, ok := supportedHeaderNames[h]; !ok {
			log.Printf("unsupported header: %s\n", h)
			return verifyTokenError
		}
	}
	a, ok := tokenAlgorithms[jwtToken.Header.Alg]
	if !ok {
		log.Printf("unknown JWS algorithm: %s\n", jwtToken.Header.Alg)
		return verifyTokenError
	}
	if jwtPlugin.alg != "" && jwtToken.Header.Alg != jwtPlugin.alg {
		log.Printf("incorrect alg, expected %s got %s\n", jwtPlugin.alg, jwtToken.Header.Alg)
		return verifyTokenError
	}
	if e := a.verify(jwtPlugin.rsa, a.hash, jwtToken.Plaintext, jwtToken.Signature); e != nil {
		log.Printf("Verify Error %+v\n", e)
		return verifyTokenError
	}
	return nil
}

func isExpire(ctime int64) bool {
	return ctime < (time.Now().UnixNano() / 1000000000)
}
