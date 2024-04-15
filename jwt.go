package ladle

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (i Issuer) CreateJWT(data Payload) (string, error) {

	if i.SecretKey == "" {
		return "", errors.New("empty secret key")
	}

	expirationTime := time.Now().Add(time.Minute * 30)
	claims := JWTClaims{
		Data: data,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    i.ProjectName,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(i.SecretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil

}

func (i Issuer) ValidateJWT(ctx context.Context, tokenString string) (context.Context, error) {

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(i.SecretKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, errors.New("error reading claims in jwt")
	}

	contextWithClaims := context.WithValue(ctx, Claimtype("claims"), claims)

	return contextWithClaims, nil
}
