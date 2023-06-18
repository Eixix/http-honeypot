package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/http"
	"os"
	"strconv"
)

var requests int = 0

func handleIndex(w http.ResponseWriter, r *http.Request) {
	requests++
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "hello </br>")
}

func handleMetricsAuth(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if ok {
		usernameHash := sha256.Sum256([]byte(username))
		passwordHash := sha256.Sum256([]byte(password))
		expectedUsernameHash := sha256.Sum256([]byte(os.Getenv("AUTH_USERNAME")))
		expectedPasswordHash := sha256.Sum256([]byte(os.Getenv("AUTH_USERNAME")))

		usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1
		passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1

		if usernameMatch && passwordMatch {
			displayMetrics(w, r)
		} else {
			handleIndex(w, r)
		}
	}
}

func displayMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "http_requests_total " + strconv.Itoa(requests))
}

func main() {
	fmt.Printf("Starting Server\n")
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/metrics", handleMetricsAuth)
	http.ListenAndServe(":8080", nil)
}
