package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
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
	localHostIP       = "127.0.0.1"
	headerContentType = "Content-Type"
	contentTypeHTML   = "text/html; charset=utf-8"
	netstatPath       = `C:\Windows\System32\netstat.exe`
	tsharkPath        = `C:\Program Files\Wireshark\tshark.exe`
)

var (
	dbMutex          sync.Mutex
	serverToken      string
	csrfToken        string
	conexionesVistas = make(map[string]bool)
)

func registrarIncidente(dbPath string, inc Incidente) {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	var lista []Incidente
	if file, err := os.Open(dbPath); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var item Incidente
			if err := json.Unmarshal(scanner.Bytes(), &item); err == nil {
				lista = append(lista, item)
			}
		}
		file.Close()
	}
	lista = append(lista, inc)
	if len(lista) > 500 {
		lista = lista[len(lista)-500:]
	}
	if file, err := os.OpenFile(dbPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
		for _, item := range lista {
			b, _ := json.Marshal(item)
			file.Write(b)
			file.WriteString("\n")
		}
		file.Close()
	}
}

func leerIncidentes(dbPath string) []Incidente {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	var lista []Incidente
	if file, err := os.Open(dbPath); err == nil {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var item Incidente
			if err := json.Unmarshal(scanner.Bytes(), &item); err == nil {
				lista = append(lista, item)
			}
		}
		file.Close()
	}
	if lista == nil {
		lista = []Incidente{}
	}
	return lista
}

func generarIDUnico() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func aplicarCabeceras(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'none'")
}

func validarSesion(r *http.Request) bool {
	c, err := r.Cookie("tr3yes_session")
	return err == nil && subtle.ConstantTimeCompare([]byte(c.Value), []byte(serverToken)) == 1
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	aplicarCabeceras(w, r)
	if r.Method == http.MethodPost {
		r.ParseForm()
		if subtle.ConstantTimeCompare([]byte(r.FormValue("token")), []byte(serverToken)) == 1 {
			http.SetCookie(w, &http.Cookie{Name: "tr3yes_session", Value: serverToken, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	w.Header().Set(headerContentType, contentTypeHTML)
	loginBytes, _ := staticFiles.ReadFile("static/login.html")
	w.Write(loginBytes)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	aplicarCabeceras(w, r)
	if !validarSesion(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.Header().Set(headerContentType, contentTypeHTML)
	indexBytes, _ := staticFiles.ReadFile("static/index.html")
	w.Write(indexBytes)
}

func main() {
	serverToken = "tr3yes_sec_2026"
	csrfBytes := make([]byte, 16)
	rand.Read(csrfBytes)
	csrfToken = hex.EncodeToString(csrfBytes)

	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/", handleDashboard)
	
	server := &http.Server{
		Addr: "127.0.0.1:8443",
		ReadTimeout: 5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	fmt.Println("[+] TR3YES SOC - Servidor Seguro en https://127.0.0.1:8443/")
	log.Fatal(server.ListenAndServeTLS("", ""))
}
