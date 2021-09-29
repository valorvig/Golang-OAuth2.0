package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
)

type customClaims struct {
	jwt.StandardClaims // embedded standard claims within the custom claims
	SID                string
}

var key = []byte("my secret key james bond 007 is an old series from my childhood")

// session id
func createToken(sid string) (string, error) {
	cc := customClaims{
		// https://tools.ietf.org/html/rfc7519#section-4.1
		StandardClaims: jwt.StandardClaims{ // type embedding
			/*
				func (t Time) Add(d Duration) Time
				- Add returns the time t+d.
				func Unix(sec int64, nsec int64) Time
				- Unix returns the local Time corresponding to the given Unix time, sec seconds and nsec nanoseconds since January 1, 1970 UTC.
			*/
			ExpiresAt: time.Now().Add(time.Minute).Unix(), // Add 1 minute since Unix time, Unix doesn't care about timezone
		},
		SID: sid,
	}

	// creat a token with claims
	// func NewWithClaims(method SigningMethod, claims Claims) *Token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, cc) // you may also create a token without using claims - func New(method SigningMethod) *Token
	// Get the complete, signed token
	// func (t *Token) SignedString(key interface{}) (string, error)
	st, err := token.SignedString(key) // st is signed token (string)
	if err != nil {
		return "", fmt.Errorf("couldn't sign token in createToken %w", err)
	}
	return st, nil
}

// return id and check if it fails
func parseToken(st string) (string, error) {
	// func ParseWithClaims(tokenString string, claims Claims, keyFunc Keyfunc) (*Token, error)
	// type Keyfunc func(*Token) (interface{}, error)
	// Parse methods use this callback function to supply the key for verification.
	token, err := jwt.ParseWithClaims(st, &customClaims{}, func(t *jwt.Token) (interface{}, error) {
		// In real cases, you may have many keys and need to choose one. We could also verify logics here.
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, errors.New("parseWithClaims different algorithms used")
		}
		return key, nil // return key to ParseWithClaims
	})

	if err != nil {
		return "", fmt.Errorf("couldn't ParseWithClaims in parsetoken %w", err)
	}

	if !token.Valid {
		return "", fmt.Errorf("token not valid in parsetoken")
	}

	// assert if it's type *customeClaims, then grab the SID from our customClaims
	return token.Claims.(*customClaims).SID, nil
}
