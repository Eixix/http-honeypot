package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

var (
	logger *log.Logger
)

type Record struct {
	RemoteAddr   string      `json:"remoteaddr"`
	Method       string      `json:"method"`
	RequestURI   string      `json:"requesturi"`
	Headers      http.Header `json:"headers"`
	UserAgent    string      `json:"UserAgent"`
	PostForm     url.Values  `json:"postform"`
	EventTime    uint64      `json:"eventtime"`
	HoneypotName string      `json:"honeypotname"`
}

func GenerateRecord(r *http.Request) Record {
	data := Record{}
	data.RemoteAddr = r.RemoteAddr
	data.Method = r.Method
	data.RequestURI = r.RequestURI
	data.Headers = r.Header
	data.UserAgent = r.UserAgent()
	r.ParseForm()
	data.PostForm = r.PostForm
	data.EventTime = uint64(time.Now().Unix())
	data.HoneypotName = "honeypot-us-west1"

	return data
}

func LogRecord(r Record) error {
	r_json, err := json.Marshal(r)
	if err != nil {
		return err
	}
	logger.Println(string(r_json))

	return nil
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	record := GenerateRecord(r)
	if err := LogRecord(record); err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "hello </br>")
}

func main() {
	// setup logging
	if logfile, err := os.OpenFile("honeypot.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666); err == nil {
		logger = log.New(logfile, "", 0)
	} else {
		log.Fatal(err)
	}

	fmt.Printf("Starting Server\n")
	http.HandleFunc("/", handleIndex)
	http.ListenAndServe(":8080", nil)
}