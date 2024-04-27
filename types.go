package ladle

import "github.com/golang-jwt/jwt/v5"

type Issuer struct {
	ProjectName string
	SecretKey   string
}

type JWTClaims struct {
	jwt.RegisteredClaims
	Id        uint
	FirstName string
}

// because context keys need custom type
type Claims string
