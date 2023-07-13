package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
	"os"
)

var (
	requests = promauto.NewCounter(prometheus.CounterOpts{
		Name: "honeypot_requests_total",
		Help: "The total number of requests",
	})
)

func handleIndex(w http.ResponseWriter, r *http.Request) {
	go func() { requests.Inc() }()
	fmt.Printf(requests)
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprintf(w, "hello </br>")
}

func handleMetricsAuth(w http.ResponseWriter, r *http.Request) {
	username, password, ok := r.BasicAuth()
	if ok {
		usernameHash := sha256.Sum256([]byte(username))
		passwordHash := sha256.Sum256([]byte(password))
		expectedUsernameHash := sha256.Sum256([]byte(os.Getenv("AUTH_USERNAME")))
		expectedPasswordHash := sha256.Sum256([]byte(os.Getenv("AUTH_PASSWORD")))

		usernameMatch := subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1
		passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1

		if usernameMatch && passwordMatch {
			promHandler := promhttp.Handler()
			promHandler.ServeHTTP(w, r)
		} else {
			handleIndex(w, r)
		}
	} else {
		handleIndex(w, r)
	}
}

func displayMetrics(w http.ResponseWriter, r *http.Request) {

}

func main() {
	fmt.Printf("Starting Server\n")
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/metrics", handleMetricsAuth)
	http.ListenAndServe(":8080", nil)
}
