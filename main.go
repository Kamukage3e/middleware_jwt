package main

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/dgrijalva/jwt-go"
)
var secretKey = []byte(os.Getenv("SECRET_KEY"))

type JWTValidationMiddleware struct {
	Next http.Handler
}

func (m *JWTValidationMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request){
	//http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		tokenString :=r.URL.Query().Get("token")

		if tokenString == ""{
			http.Error(w, "Token not found in the query parameter", http.StatusUnauthorized)
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Invalid signing method")
			}
			return secretKey, nil
		})
		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if token.Valid {
			claims, ok := token.Claims.(jwt.MapClaims)
			if ok{
				name := claims["name"].(string)
				url := claims["url"].(string)
				sub := claims["sub"].(string)
				iss := claims["iss"].(string)
				iatFloat, ok := claims["iat"].(float64)
				if !ok {
					http.Error(w, "invalid issued time", http.StatusUnauthorized)
				}
				iatUnix := int64(iatFloat)
				iat := time.Unix(iatUnix, 0)

				expFloat, ok := claims["exp"].(float64)
				if !ok {
					http.Error(w, "invalid issued time", http.StatusUnauthorized)
				}
				expUnix := int64(expFloat)
				exp := time.Unix(expUnix, 0)

				eid := claims["eid"].(string)
				fmt.Println(w, "Welcome, %s! Your role is %s.", name, url, iss, sub, iat, exp, eid)
				
			} else {
				http.Error(w, "Invalid token payload", http.StatusUnauthorized)
			}
		} else {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
		}
	}

func NewJWTValidationMiddleware(next http.Handler) *JWTValidationMiddleware {
	return &JWTValidationMiddleware{Next: next}
}
