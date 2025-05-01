package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func keyFunc(tokenSecret string) jwt.Keyfunc {
	return func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	}
}

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func CheckPasswordHash(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn).UTC()),
		Subject:   userID.String(),
	}).SignedString([]byte(tokenSecret))
	if err != nil {
		return "", err
	}
	return token, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, keyFunc(tokenSecret))
	if err != nil {
		return uuid.UUID{}, err
	}
	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok {
		userID, err := uuid.Parse(claims.Subject)
		if err != nil {
			return uuid.UUID{}, err
		}
		return userID, nil
	}
	return uuid.UUID{}, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	headerValue := headers.Get("Authorization")
	if headerValue == "" {
		return "", nil
	}
	words := strings.Fields(headerValue)
	if len(words) != 2 || strings.ToLower(words[0]) != "bearer" {
		return "", nil
	}
	return words[1], nil
}

func MakeRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes), nil
}
