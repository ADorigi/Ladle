package ladle

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func NewIssuer(projectname string, secretKey string) Issuer {
	return Issuer{
		ProjectName: projectname,
		SecretKey:   secretKey,
	}
}

func (i Issuer) NewJWTClaims(id uint, firstname string) *JWTClaims {

	expirationTime := time.Now().Add(time.Minute * 30) // 30 minutes from now

	return &JWTClaims{
		Id:        id,
		FirstName: firstname,
		RegisteredClaims: jwt.RegisteredClaims{
			// Also fixed dates can be used for the NumericDate
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			Issuer:    i.ProjectName,
		},
	}
}

func (i Issuer) CreateJWT(claims *JWTClaims) (string, error) {

	if i.SecretKey == "" {
		return "", errors.New("empty secret key")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, *claims)

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

	contextWithClaims := context.WithValue(ctx, Claims("claims"), claims)

	return contextWithClaims, nil
}
