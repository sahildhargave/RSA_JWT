package db

import (
	"errors"
	"log"
	"rsa/db/models"
	"rsa/utils/random"

	"golang.org/x/crypto/bcrypt"
)

var users = map[string]models.User{}
var refreshTokens map[string]string

func InitDB() {
	refreshTokens = make(map[string]string)
}

func StoreUser(username string, password string, role string) (uuid string, err error) {
	uuid, err = random.GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	// check to make sure our uuid is unique
	u := models.User{}
	for u != users[uuid] {
		uuid, err = random.GenerateRandomString(32)
		if err != nil {
			return "", err
		}
	}

	// generate the bcrypt password hash
	passwordHash, hashErr := generateBcryptHash(password)
	if hashErr != nil {
		err = hashErr
		return
	}

	users[uuid] = models.User{username, passwordHash, role}

	return uuid, err
}

func DeleteUser(uuid string) {
	delete(users, uuid)
}

func FetchUserById(uuid string) (models.User, error) {
	u := users[uuid]
	blankUser := models.User{}

	if blankUser != u {
		return u, nil
	} else {
		return models.User{}, errors.New("User not found that matches given uuid")
	}
}

func FetchUserByUsername(username string) (models.User, string, error) {
	for k, v := range users {
		if v.Username == username {
			return v, k, nil
		}
	}
	return models.User{}, "", errors.New("User Not Found That matches given username")
}

func StoreRefreshToken() (jwt string, err error) {
	jwt, err = random.GenerateRandomString(32)
	if err != nil {
		return jwt, err
	}

	for refreshTokens[jwt] != "" {
		jwt, err = random.GenerateRandomString(32)
		if err != nil {
			return jwt, err
		}
	}

	refreshTokens[jwt] = "valid"

	return jwt, err
}

func DeleteRefreshToken(jwt string) {
	delete(refreshTokens, jwt)
}

func CheckRefreshToken(jwt string) bool {
	return refreshTokens[jwt] != ""
}

func LogUserIn(username string, password string) (models.User, string, error) {
	user, uuid, userErr := FetchUserByUsername(username)
	log.Println(user, uuid, userErr)
	if userErr != nil {
		return models.User{}, "", userErr
	}
	return user, uuid, checkPasswordAgainstHash(user.PasswordHash, password)
}

func generateBcryptHash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash[:]), err
}

func checkPasswordAgainstHash(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
