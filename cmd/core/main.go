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

//go:embed web/*
var webAssets embed.FS

type Incidente struct {
	ID          string `json:"id"`
	Timestamp   string `json:"timestamp"`
	Source      string `json:"source"`
	EventType   string `json:"event_type"`
	MitreID     string `json:"mitre_id"`
	Description string `json:"description"`
	Status      string `json:"status"`
}

type LoginAttempt struct {
	failures  int
	lockUntil time.Time
}

type EnrichRequest struct {
	IP string `json:"ip"`
}

type BlockRequest struct {
	IP string `json:"ip"`
	ID string `json:"id"`
}

type StatusRequest struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

type DeleteRequest struct {
	ID string `json:"id"`
}

type EngineToggleResponse struct {
	Paused bool `json:"paused"`
}

type AnalysisStats struct {
	Harmless   int `json:"harmless"`
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Undetected int `json:"undetected"`
}

type Attributes struct {
	LastAnalysisStats AnalysisStats `json:"last_analysis_stats"`
}

type VTData struct {
	Attributes Attributes `json:"attributes"`
}

type VirusTotalResponse struct {
	Data VTData `json:"data"`
}

const (
	localHostIP       = "127.0.0.1"
	headerContentType = "Content-Type"
	contentTypeHTML   = "text/html; charset=utf-8"
	netshPath         = `C:\Windows\System32\netsh.exe`
	netstatPath       = `C:\Windows\System32\netstat.exe`
	tsharkPath        = `C:\Program Files\Wireshark\tshark.exe`
)

var (
	dbMutex          sync.Mutex
	blockedIPs       = make(map[string]bool)
	soarMutex        sync.Mutex
	serverToken      string
	csrfToken        string
	loginAttempts    = make(map[string]*LoginAttempt)
	attemptsMutex    sync.Mutex
	conexionesVistas = make(map[string]bool)
	tsharkVistos     = make(map[string]bool)
)

func registrarIncidente(dbPath string, inc Incidente) {
	soarMutex.Lock()
	for ip := range blockedIPs {
		if strings.Contains(inc.Description, ip) {
			inc.Status = "SOAR_BLOQUEADO"
			inc.Description = "[FIREWALL DROP] " + inc.Description
		}
	}
	soarMutex.Unlock()

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
	if len(lista) > 1000 {
		lista = lista[len(lista)-1000:]
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

func escribirIncidentes(dbPath string, lista []Incidente) {
	dbMutex.Lock()
	defer dbMutex.Unlock()
	if file, err := os.OpenFile(dbPath, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0600); err == nil {
		for _, item := range lista {
			b, _ := json.Marshal(item)
			file.Write(b)
			file.WriteString("\n")
		}
		file.Close()
	}
}

func generarIDUnico() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func procesarLineaConexionRed(dbPath, linea string) {
	campos := strings.Fields(linea)
	if len(campos) < 4 || !strings.Contains(linea, "ESTABLISHED") {
		return
	}
	remoto := campos[2]
	partes := strings.Split(remoto, ":")
	if len(partes) != 2 {
		return
	}
	ipRemota := partes[0]
	puertoRemoto := partes[1]

	if ipRemota == localHostIP || ipRemota == "0.0.0.0" {
		return
	}
	if !conexionesVistas[ipRemota] {
		conexionesVistas[ipRemota] = true
		go func(ip, puerto string) {
			nombres, _ := net.LookupAddr(ip)
			dominio := "[Sin Dominio Público]"
			if len(nombres) > 0 {
				dominio = strings.TrimRight(nombres[0], ".")
			}
			registrarIncidente(dbPath, Incidente{
				ID:          generarIDUnico(),
				Timestamp:   time.Now().Format(time.RFC3339),
				Source:      "Host-Sensor",
				EventType:   "Conexión Externa Real TCP",
				MitreID:     "T1049 (System Network Connections)",
				Description: fmt.Sprintf("[HIDS] Nueva conexión establecida -> IP: %s | Puerto: %s | Dominio(rDNS): %s", ip, puerto, dominio),
				Status:      "Nuevo",
			})
		}(ipRemota, puertoRemoto)
	}
}

func monitorearRedReal(dbPath string, paused *bool, mu *sync.Mutex) {
	mu.Lock()
	p := *paused
	mu.Unlock()
	if p {
		return
	}

	cmd := exec.Command(netstatPath, "-n", "-p", "tcp") //NOSONAR
	out, err := cmd.Output()
	if err != nil {
		return
	}
	lineas := strings.Split(string(out), "\n")
	for _, linea := range lineas {
		procesarLineaConexionRed(dbPath, linea)
	}
}

func monitorearTshark(dbPath string, paused *bool, mu *sync.Mutex) {
	iface := os.Getenv("TR3YES_IFACE")
	if iface == "" {
		iface = "5"
	}

	args := []string{"-l", "-Y", "tls.handshake.type == 1", "-T", "fields", "-e", "ip.dst", "-e", "tls.handshake.extensions_server_name"}
	if iface != "" {
		args = append([]string{"-i", iface}, args...)
	}

	cmd := exec.Command(tsharkPath, args...) //NOSONAR
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	if err := cmd.Start(); err != nil {
		log.Println("[!] ADVERTENCIA: Tshark no detectado en el PATH.")
		return
	}
	log.Printf("[+] 🦈 Sensor TSHARK ACTIVO (Interfaz: %s): Escuchando URLs...", iface)

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		mu.Lock()
		p := *paused
		mu.Unlock()
		if p {
			continue
		}
		campos := strings.Fields(scanner.Text())
		if len(campos) >= 2 {
			ipDest := campos[0]
			urlDominio := campos[1]
			if ipDest == localHostIP {
				continue
			}
			llaveUnica := ipDest + "-" + urlDominio
			if !tsharkVistos[llaveUnica] {
				tsharkVistos[llaveUnica] = true
				registrarIncidente(dbPath, Incidente{ID: generarIDUnico(), Timestamp: time.Now().Format(time.RFC3339), Source: "Tshark", EventType: "Intercepción HTTPS (SNI)", MitreID: "T1071.001 (Application Layer Protocol)", Description: fmt.Sprintf("[TSHARK] Petición TLS detectada hacia el dominio: %s (IP Destino: %s)", urlDominio, ipDest), Status: "Nuevo"})
			}
		}
	}
}

func monitorearTcpdump(dbPath string, paused *bool, mu *sync.Mutex) {
	iface := os.Getenv("TR3YES_IFACE")
	if iface == "" {
		iface = "5"
	}

	args := []string{"-l", "-n", "-f", "port 53"}
	if iface != "" {
		args = append([]string{"-i", iface}, args...)
	}

	cmd := exec.Command(tsharkPath, args...) //NOSONAR
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return
	}

	if err := cmd.Start(); err != nil {
		log.Println("[!] ADVERTENCIA: Motor de captura RAW no detectado.")
		return
	}
	log.Printf("[+] 🛡️ Sensor TCPDUMP BPF ACTIVO (Interfaz: %s): Escuchando DNS en crudo...", iface)

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		mu.Lock()
		p := *paused
		mu.Unlock()
		if p {
			continue
		}
		linea := scanner.Text()

		if !strings.Contains(linea, localHostIP) {
			longitudMaxima := 150
			if len(linea) < longitudMaxima {
				longitudMaxima = len(linea)
			}
			registrarIncidente(dbPath, Incidente{ID: generarIDUnico(), Timestamp: time.Now().Format(time.RFC3339), Source: "Tcpdump", EventType: "Captura de Paquete en Crudo", MitreID: "T1040 (Network Sniffing)", Description: fmt.Sprintf("[TCPDUMP RAW] %s", linea[:longitudMaxima]), Status: "Nuevo"})
		}
	}
}

func generarCertificadoTLS() tls.Certificate {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"tr3yes Security Operations"}, CommonName: "localhost"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{net.ParseIP(localHostIP)},
		DNSNames:              []string{"localhost"},
		BasicConstraintsValid: true,
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	pemCert := fmt.Sprintf("-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n", encodeBase64(derBytes))
	pemKey := fmt.Sprintf("-----BEGIN EC PRIVATE KEY-----\n%s\n-----END EC PRIVATE KEY-----\n", encodeBase64(privBytes))
	cert, _ := tls.X509KeyPair([]byte(pemCert), []byte(pemKey))
	return cert
}

func encodeBase64(b []byte) string {
	const base64Table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var buf strings.Builder
	for i := 0; i < len(b); i += 3 {
		remaining := len(b) - i
		val := uint(b[i]) << 16
		if remaining > 1 {
			val |= uint(b[i+1]) << 8
		}
		if remaining > 2 {
			val |= uint(b[i+2])
		}
		for j := 0; j < 4; j++ {
			if remaining*6 < j*6 && remaining < 3 && j > remaining {
				buf.WriteByte('=')
			} else {
				idx := (val >> uint(6*(3-j))) & 0x3F
				buf.WriteByte(base64Table[idx])
			}
		}
		if buf.Len()%76 == 0 {
			buf.WriteByte('\n')
		}
	}
	return buf.String()
}

func obtenerTokenSeguro() string {
	if envToken := os.Getenv("TR3YES_TOKEN"); envToken != "" {
		return envToken
	}
	tokenBytes := make([]byte, 16)
	rand.Read(tokenBytes)
	return hex.EncodeToString(tokenBytes)
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

func validarCSRF(r *http.Request) bool {
	clientToken := r.Header.Get("X-CSRF-Token")
	return subtle.ConstantTimeCompare([]byte(clientToken), []byte(csrfToken)) == 1
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	aplicarCabeceras(w, r)
	ip := r.RemoteAddr
	if strings.Contains(ip, ":") {
		ip, _, _ = net.SplitHostPort(ip)
	}
	if ip == "" {
		ip = localHostIP
	}

	attemptsMutex.Lock()
	attempt, exists := loginAttempts[ip]
	if exists && attempt.lockUntil.After(time.Now()) {
		tiempoRestante := int(time.Until(attempt.lockUntil).Seconds())
		attemptsMutex.Unlock()

		w.Header().Set(headerContentType, contentTypeHTML)
		w.WriteHeader(http.StatusTooManyRequests)
		loginBytes, _ := webAssets.ReadFile("web/login.html")
		w.Write(loginBytes)
		return
	}
	attemptsMutex.Unlock()

	if r.Method == http.MethodPost {
		r.ParseForm()
		ingreso := r.FormValue("token")
		attemptsMutex.Lock()
		if subtle.ConstantTimeCompare([]byte(ingreso), []byte(serverToken)) == 1 {
			delete(loginAttempts, ip)
			attemptsMutex.Unlock()
			http.SetCookie(w, &http.Cookie{Name: "tr3yes_session", Value: serverToken, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		if !exists {
			attempt = &LoginAttempt{}
			loginAttempts[ip] = attempt
		}
		attempt.failures++
		if attempt.failures >= 3 {
			attempt.lockUntil = time.Now().Add(30 * time.Second)
			attempt.failures = 0
		}
		attemptsMutex.Unlock()
	}
	w.Header().Set(headerContentType, contentTypeHTML)
	loginBytes, _ := webAssets.ReadFile("web/login.html")
	w.Write(loginBytes)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	aplicarCabeceras(w, r)
	if !validarSesion(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.Header().Set(headerContentType, contentTypeHTML)
	indexBytes, _ := webAssets.ReadFile("web/index.html")
	htmlFinal := strings.Replace(string(indexBytes), "{{CSRF_TOKEN}}", csrfToken, 1)
	w.Write([]byte(htmlFinal))
}

func handleAPIEvents(w http.ResponseWriter, r *http.Request, dbPath string) {
	aplicarCabeceras(w, r)
	if !validarSesion(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set(headerContentType, "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(leerIncidentes(dbPath))
}

func handleAPIEnrich(w http.ResponseWriter, r *http.Request) {
	aplicarCabeceras(w, r)
	if !validarSesion(r) || !validarCSRF(r) || r.Method != http.MethodPost {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var req EnrichRequest
	json.NewDecoder(r.Body).Decode(&req)
	vtKey := os.Getenv("VT_API_KEY")
	w.Header().Set(headerContentType, "application/json")
	if vtKey == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "OPSEC: Variable VT_API_KEY no configurada."})
		return
	}

	url := "https://www.virustotal.com/api/v3/ip-addresses/" + req.IP
	client := &http.Client{Timeout: 10 * time.Second}
	httpReq, _ := http.NewRequest("GET", url, nil)
	httpReq.Header.Add("x-apikey", vtKey)
	resp, err := client.Do(httpReq)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": "Fallo al conectar con la red externa."})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		json.NewEncoder(w).Encode(map[string]interface{}{"message": "[🛡️ VT INTEL] IP sin registros previos.", "malicious": 0})
		return
	} else if resp.StatusCode != 200 {
		json.NewEncoder(w).Encode(map[string]interface{}{"error": fmt.Sprintf("Fallo en API VirusTotal (HTTP %d).", resp.StatusCode)})
		return
	}

	var vtResp VirusTotalResponse
	json.NewDecoder(resp.Body).Decode(&vtResp)
	stats := vtResp.Data.Attributes.LastAnalysisStats
	msg := fmt.Sprintf("[🛡️ VT INTEL] Score: %d Maliciosos | %d Sospechosos | %d Limpios", stats.Malicious, stats.Suspicious, stats.Harmless)
	json.NewEncoder(w).Encode(map[string]interface{}{"message": msg, "malicious": stats.Malicious})
}

func handleAPIBlock(w http.ResponseWriter, r *http.Request, dbPath string) {
	aplicarCabeceras(w, r)
	if !validarSesion(r) || !validarCSRF(r) || r.Method != http.MethodPost {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var req BlockRequest
	json.NewDecoder(r.Body).Decode(&req)

	if req.IP != "" {
		parsedIP := net.ParseIP(req.IP)
		if parsedIP == nil {
			http.Error(w, "Invalid IP Format", http.StatusBadRequest)
			return
		}
		safeIP := parsedIP.String()

		soarMutex.Lock()
		blockedIPs[safeIP] = true
		soarMutex.Unlock()

		ruleNameIn := fmt.Sprintf("TR3YES_BLOCK_IN_%s", safeIP)
		ruleNameOut := fmt.Sprintf("TR3YES_BLOCK_OUT_%s", safeIP)

		exec.Command(netshPath, "advfirewall", "firewall", "add", "rule", "name="+ruleNameIn, "dir=in", "action=block", "remoteip="+safeIP).Run()  //NOSONAR
		exec.Command(netshPath, "advfirewall", "firewall", "add", "rule", "name="+ruleNameOut, "dir=out", "action=block", "remoteip="+safeIP).Run() //NOSONAR
	}

	lista := leerIncidentes(dbPath)
	for i, ev := range lista {
		if ev.ID == req.ID || (req.IP != "" && strings.Contains(ev.Description, req.IP)) {
			lista[i].Status = "SOAR_BLOQUEADO"
			if !strings.Contains(lista[i].Description, "[FW NATIVO]") {
				lista[i].Description = "[FW NATIVO] " + lista[i].Description
			}
		}
	}
	escribirIncidentes(dbPath, lista)
	w.WriteHeader(http.StatusOK)
}

func handleAPIStatus(w http.ResponseWriter, r *http.Request, dbPath string) {
	aplicarCabeceras(w, r)
	if !validarSesion(r) || !validarCSRF(r) || r.Method != http.MethodPost {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var req StatusRequest
	json.NewDecoder(r.Body).Decode(&req)
	lista := leerIncidentes(dbPath)
	for i, ev := range lista {
		if ev.ID == req.ID {
			lista[i].Status = req.Status
		}
	}
	escribirIncidentes(dbPath, lista)
	w.WriteHeader(http.StatusOK)
}

func handleAPIDelete(w http.ResponseWriter, r *http.Request, dbPath string) {
	aplicarCabeceras(w, r)
	if !validarSesion(r) || !validarCSRF(r) || r.Method != http.MethodPost {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var req DeleteRequest
	json.NewDecoder(r.Body).Decode(&req)
	lista := leerIncidentes(dbPath)
	var nuevaLista []Incidente
	for _, ev := range lista {
		if ev.ID != req.ID {
			nuevaLista = append(nuevaLista, ev)
		}
	}
	escribirIncidentes(dbPath, nuevaLista)
	w.WriteHeader(http.StatusOK)
}

func handleAPIClear(w http.ResponseWriter, r *http.Request, dbPath string) {
	aplicarCabeceras(w, r)
	if !validarSesion(r) || !validarCSRF(r) || r.Method != http.MethodPost {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	conexionesVistas = make(map[string]bool)
	tsharkVistos = make(map[string]bool)
	escribirIncidentes(dbPath, []Incidente{})
	w.WriteHeader(http.StatusOK)
}

func handleAPIToggle(w http.ResponseWriter, r *http.Request, engineMu *sync.Mutex, enginePaused *bool) {
	aplicarCabeceras(w, r)
	if !validarSesion(r) || !validarCSRF(r) || r.Method != http.MethodPost {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	engineMu.Lock()
	*enginePaused = !*enginePaused
	p := *enginePaused
	engineMu.Unlock()
	w.Header().Set(headerContentType, "application/json")
	json.NewEncoder(w).Encode(EngineToggleResponse{Paused: p})
}

func configurarRutasHTTP(dbPath string, engineMu *sync.Mutex, enginePaused *bool) {
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/", handleDashboard)
	http.HandleFunc("/ui.css", func(w http.ResponseWriter, r *http.Request) {
		aplicarCabeceras(w, r)
		w.Header().Set(headerContentType, "text/css; charset=utf-8")
		cssBytes, _ := webAssets.ReadFile("web/ui.css")
		w.Write(cssBytes)
	})
	http.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		aplicarCabeceras(w, r)
		w.Header().Set(headerContentType, "application/javascript; charset=utf-8")
		jsBytes, _ := webAssets.ReadFile("web/app.js")
		w.Write(jsBytes)
	})
	http.HandleFunc("/api/events", func(w http.ResponseWriter, r *http.Request) {
		handleAPIEvents(w, r, dbPath)
	})
	http.HandleFunc("/api/soar/enrich", handleAPIEnrich)
	http.HandleFunc("/api/soar/block-ip", func(w http.ResponseWriter, r *http.Request) {
		handleAPIBlock(w, r, dbPath)
	})
	http.HandleFunc("/api/event/status", func(w http.ResponseWriter, r *http.Request) {
		handleAPIStatus(w, r, dbPath)
	})
	http.HandleFunc("/api/event/delete", func(w http.ResponseWriter, r *http.Request) {
		handleAPIDelete(w, r, dbPath)
	})
	http.HandleFunc("/api/events/clear", func(w http.ResponseWriter, r *http.Request) {
		handleAPIClear(w, r, dbPath)
	})
	http.HandleFunc("/api/engine/toggle", func(w http.ResponseWriter, r *http.Request) {
		handleAPIToggle(w, r, engineMu, enginePaused)
	})
}

func main() {
	host := localHostIP
	port := "8443"
	dbPath := "tr3yes_splunk_audit.json"

	serverToken = obtenerTokenSeguro()
	csrfBytes := make([]byte, 16)
	rand.Read(csrfBytes)
	csrfToken = hex.EncodeToString(csrfBytes)

	var enginePaused bool
	var engineMu sync.Mutex

	go func() {
		ticker := time.NewTicker(3 * time.Second)
		for range ticker.C {
			monitorearRedReal(dbPath, &enginePaused, &engineMu)
		}
	}()

	go monitorearTshark(dbPath, &enginePaused, &engineMu)
	go monitorearTcpdump(dbPath, &enginePaused, &engineMu)

	configurarRutasHTTP(dbPath, &engineMu, &enginePaused)

	tlsCert := generarCertificadoTLS()
	server := &http.Server{
		Addr: fmt.Sprintf("%s:%s", host, port),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{tlsCert},
		},
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	fmt.Println("==========================================================")
	fmt.Println("[+] TR3YES SOC (Triple Sensor / Go Embed)")
	fmt.Println("[+] URL DE ACCESO: https://127.0.0.1:8443/")
	if os.Getenv("TR3YES_TOKEN") != "" {
		fmt.Println("[+] TOKEN CARGADO DESDE VARIABLE DE ENTORNO")
	} else {
		fmt.Printf("[+] TOKEN EFÍMERO EN RAM (COPIAR): %s\n", serverToken)
	}
	fmt.Println("==========================================================")
	log.Fatal(server.ListenAndServeTLS("", ""))
}
