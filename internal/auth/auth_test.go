// filepath: /home/knasta1/repos/boot.dev/chirpy/internal/auth/auth_test.go
package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func TestValidateJWT(t *testing.T) {
	tokenSecret := "testsecret"
	userID := uuid.New()
	expiresIn := time.Minute * 5

	t.Run("Valid JWT", func(t *testing.T) {
		token, err := MakeJWT(userID, tokenSecret, expiresIn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		fmt.Println("Token:", token)

		parsedUserID, err := ValidateJWT(token, tokenSecret)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if userID != parsedUserID {
			t.Fatalf("expected user id %s and parsed id %s to be equal", userID, parsedUserID)
		}
	})

	t.Run("Invalid JWT - Incorrect Secret", func(t *testing.T) {
		token, err := MakeJWT(userID, tokenSecret, expiresIn)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err = ValidateJWT(token, "wrongsecret")
		if err == nil {
			t.Fatalf("expected an error")
		}
	})

	t.Run("Expired JWT", func(t *testing.T) {
		token, err := MakeJWT(userID, tokenSecret, -time.Minute)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err = ValidateJWT(token, tokenSecret)
		if err == nil {
			t.Fatalf("expected an error")
		}
	})

	t.Run("Invalid JWT Format", func(t *testing.T) {
		_, err := ValidateJWT("invalid.token.string", tokenSecret)
		if err == nil {
			t.Fatalf("expected an error")
		}
	})

	t.Run("Missing Claims", func(t *testing.T) {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{})
		tokenString, err := token.SignedString([]byte(tokenSecret))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		_, err = ValidateJWT(tokenString, tokenSecret)
		if err == nil {
			t.Fatalf("expected an error")
		}
	})
}
