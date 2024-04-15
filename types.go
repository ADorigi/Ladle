package ladle

import "github.com/golang-jwt/jwt/v5"

type Claimtype string

type Issuer struct {
	ProjectName string
	SecretKey   string
}

type Payload struct {
	ID        string
	FirstName string
	Email     string
}

type JWTClaims struct {
	Data Payload
	jwt.RegisteredClaims
}
