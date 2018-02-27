package server

import (
	"errors"
	"io/ioutil"
	"log"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

type AuthJwt struct {
	publicKey string
}

func NewAuthJwt() *AuthJwt {
	return &AuthJwt{}
}

func (a *AuthJwt) readPublicKey(path string) error {
	data, fileErr := ioutil.ReadFile(path)
	if fileErr != nil {
		return fileErr
	}

	a.publicKey = string(data)
	return nil
}

func (a *AuthJwt) addPublicKey(publicKey string) {
	a.publicKey = publicKey
}

func (a *AuthJwt) authenticateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		publicKeyBytes, err := jwt.ParseRSAPublicKeyFromPEM([]byte(a.publicKey))
		if err != nil {
			panic(err)
		}

		return publicKeyBytes, nil
	})

	if err != nil {
		return nil, err
	}

	if token == nil {
		return nil, errors.New("Empty token")
	}

	if token.Valid {
		// nothing to do
	} else if validationError, ok := err.(jwt.ValidationError); ok {
		if validationError.Errors&jwt.ValidationErrorMalformed != 0 {
			log.Println("Malformed token.")
			return nil, validationError
		} else if validationError.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			log.Println("Token expired or not yet valid.")
			return nil, validationError
		} else {
			log.Println("You can't handle the token!")
			return nil, validationError
		}
	} else {
		log.Println("You can't handle the token!")
		return nil, validationError
	}

	return token, nil
}

func (a *AuthJwt) getJwtPermissions(token *jwt.Token) (*Permissions, error) {
	jwtPermissions := &Permissions{}
	claims := token.Claims.(jwt.MapClaims)

	if claims == nil {
		return nil, ErrInvalidClaims
	}

	permissionsClaim, _ := claims["permissions"].(string)
	if permissionsClaim == "" {
		return nil, ErrAuthorization
	}

	permissions := strings.Split(permissionsClaim, " ")
	for _, permission := range permissions {
		pkv := strings.Split(permission, ":")
		if len(pkv) != 2 {
			return nil, ErrInvalidPermissionsClaim
		}
		permType := pkv[0]
		permValue := pkv[1]
		if permType == "publish" {
			jwtPermissions.Publish = append(jwtPermissions.Publish, permValue)
		} else if permType == "subscribe" {
			jwtPermissions.Subscribe = append(jwtPermissions.Subscribe, permValue)
		} else {
			return nil, ErrInvalidPermissionsClaim
		}
	}

	return jwtPermissions, nil
}
