//🔐🔐🔏🔑🔓🔓🔑🔏🔐🔒

package models

import (
	"rsa/utils/random"
	"time"

	jwt "github.com/golang-jwt/jwt"
)

type User struct {
	Username,
	PasswordHash,
	Role string
}

type TokenClaims struct {
	jwt.StandardClaims
	Role string `json:"role"`
	Csrf string `json:"csrf"`
}

const RefreshTokenValidTime = time.Hour * 72
const AuthTokenValidTime = time.Minute * 15

func GenerateCSRFSecret() (string, error) {
	return random.GenerateRandomString(32)
}
