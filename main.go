package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type Storage struct {
	mu       sync.Mutex
	filename string
	auth     JwtAuth
}

func (s *Storage) createUser(creds *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.getAllUsers()
	if err != nil {
		return err
	}

	for _, user := range users {
		if user.Username == creds.Username {
			return fmt.Errorf("user already exists: %q", user.Username)
		}
	}

	users = append(users, *creds)

	dat, err := json.Marshal(users)
	if err != nil {
		return fmt.Errorf("cannot marshal users, \\_'>'_/")
	}

	err = ioutil.WriteFile(s.filename, dat, 0600)
	if err != nil {
		return fmt.Errorf("failed to save users: %q", err)
	}
	return nil
}

func (s *Storage) getAllUsers() ([]User, error) {
	users := []User{}
	_, err := os.Stat(s.filename)

	if os.IsNotExist(err) {
		return users, nil
	}
	if err != nil {
		return nil, err
	}

	dat, err := ioutil.ReadFile(s.filename)
	if err != nil {
		return nil, fmt.Errorf("cannot read %q: %q", s.filename, err)
	}

	err = json.Unmarshal(dat, &users)
	if err != nil {
		return nil, fmt.Errorf("cannot parse %q: %q", s.filename, err)
	}

	return users, nil
}

func (s *Storage) findByName(username string) (*User, error) {
	users, err := s.getAllUsers()
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		if user.Username == username {
			return &user, nil
		}
	}

	return nil, nil
}

type JwtClaim struct {
	User string
	jwt.StandardClaims
}

type JwtAuth struct {
	SecretKey      string
	Issuer         string
	ExpirationTime time.Duration
}

func NewAuth() JwtAuth {
	var auth JwtAuth

	secretKey := make([]byte, 20)
	rand.Read(secretKey)
	auth.SecretKey = string(secretKey)

	auth.Issuer = "qgelena"
	auth.ExpirationTime = time.Duration(600 * 1000 * 1000 * 1000)

	return auth
}

var storage Storage

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Hello Go world!")
}

func userCreate(w http.ResponseWriter, r *http.Request) {
	var user User
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&user)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "JSON error: %v", err)
		return
	}
	fmt.Printf("username=%q, password=%q\n", user.Username, user.Password)
	// TODO: check empty password

	err = storage.createUser(&user)
	if err != nil {
		// TODO: check which kind of error
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "%v", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "OK")
}

func userLogin(w http.ResponseWriter, r *http.Request) {
	// read the request data
	var reqUser User
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&reqUser)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "JSON error: %v", err)
		return
	}
	fmt.Printf("username=%q, password=%q\n", reqUser.Username, reqUser.Password)

	// check the user
	dbUser, err := storage.findByName(reqUser.Username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%v", err)
		return
	}
	if dbUser == nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "user not found: %v", reqUser.Username)
		return
	}
	if dbUser.Password != reqUser.Password {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "failed authorization")
		return
	}

	// create a new token
	exptime := time.Now().Local().Add(time.Second * storage.auth.ExpirationTime).Unix()
	claims := JwtClaim{
		User: reqUser.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: exptime,
			Issuer:    storage.auth.Issuer,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signedToken, err := token.SignedString([]byte(storage.auth.SecretKey))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to sign token")
		return
	}

	type Response struct {
		Token     string `json:"token"`
		ExpiresAt int    `json:"expires_at"`
	}
	response := Response{Token: signedToken, ExpiresAt: int(claims.ExpiresAt)}
	dat, err := json.Marshal(&response)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "failed to marshal json")
		return
	}
	w.Write(dat)
}

func btcRate(w http.ResponseWriter, r *http.Request) {

}

var address string = ":8081"

func main() {
	storage.auth = NewAuth()

	storage.filename = "users.json"
	fmt.Printf("listening on %v\n", address)

	http.HandleFunc("/", homePage)
	http.HandleFunc("/user/create", userCreate)
	http.HandleFunc("/user/login", userLogin)
	http.HandleFunc("/btcRate", btcRate)

	http.ListenAndServe(address, nil)
}
