package main

import (
	"bufio"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

//go:embed static/*
var staticFiles embed.FS

type Incidente struct {
	ID          string `json:"id"`
	Timestamp   string `json:"timestamp"`
	Source      string `json:"source"`
	EventType   string `json:"event_type"`
	MitreID     string `json:"mitre_id"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

const (
	headerContentType = "Content-Type"
	contentTypeHTML   = "text/html; charset=utf-8"
	contentTypeJSON   = "application/json; charset=utf-8"
)

var (
	dbMutex     sync.Mutex
	serverToken string
)

func leerIncidentes(dbPath string) []Incidente {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	var lista []Incidente
	file, err := os.Open(dbPath)
	if err != nil {
		return []Incidente{}
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var item Incidente
		if json.Unmarshal(scanner.Bytes(), &item) == nil {
			lista = append(lista, item)
		}
	}
	return lista
}

func aplicarCabeceras(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
}

func main() {
	serverToken = "tr3yes_sec_2026"
	dbPath := "tr3yes_splunk_audit.json"

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		aplicarCabeceras(w)
		if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(r.FormValue("token")), []byte(serverToken)) == 1 {
			http.SetCookie(w, &http.Cookie{Name: "tr3yes_session", Value: serverToken, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		w.Header().Set(headerContentType, contentTypeHTML)
		if loginBytes, err := staticFiles.ReadFile("static/login.html"); err == nil {
			w.Write(loginBytes)
		}
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		aplicarCabeceras(w)
		c, err := r.Cookie("tr3yes_session")
		if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(serverToken)) != 1 {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		w.Header().Set(headerContentType, contentTypeHTML)
		if indexBytes, err := staticFiles.ReadFile("static/index.html"); err == nil {
			w.Write(indexBytes)
		}
	})

	http.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		aplicarCabeceras(w)
		w.Header().Set(headerContentType, contentTypeJSON)
		json.NewEncoder(w).Encode(leerIncidentes(dbPath))
	})

	server := &http.Server{
		Addr:         "127.0.0.1:8443",
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	fmt.Println("[+] TR3YES SOC - Servidor Seguro en https://127.0.0.1:8443/")
	log.Fatal(server.ListenAndServeTLS("", ""))
}
