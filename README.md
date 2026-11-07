# 👁️ TR3YES - Tactical Operations Center (Local SOC/EDR)

![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go)
![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11-0078D6?style=for-the-badge&logo=windows)
![Status](https://img.shields.io/badge/Status-Production_Ready-00ff66?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)
![Author](https://img.shields.io/badge/Author-Edgar_E._Toloza-38bdf8?style=for-the-badge)

**TR3YES** es un Centro de Operaciones Tácticas (SOC) y motor EDR ligero construido en **Go**. Está diseñado para ejecutarse nativamente en entornos Windows, proporcionando monitoreo de red en tiempo real, inspección profunda de paquetes (DPI) y capacidades SOAR (Orquestación, Automatización y Respuesta) sin depender de pesados agentes de terceros.

## 🏗️ Arquitectura: El Triple Sensor

El núcleo de TR3YES opera utilizando rutinas concurrentes en Go (`goroutines`) que alimentan una base de datos forense unificada en formato JSON, capturando telemetría a través de tres motores independientes:

1. **HIDS (Host Sensor):** Emplea análisis de sockets a nivel de sistema (`netstat`) para detectar conexiones TCP establecidas, resolviendo dominios inversos (rDNS) y alertando sobre túneles salientes (Mitre T1049).
2. **TSHARK (TLS/SNI DPI):** Intercepta el tráfico encriptado en su fase inicial (Handshake TLS 1.2/1.3), extrayendo el *Server Name Indication (SNI)* para revelar los dominios de destino reales sin romper el cifrado SSL (Mitre T1071.001).
3. **TCPDUMP (BPF RAW Sockets):** Utiliza el motor de Berkeley Packet Filter integrado en Wireshark/Npcap para escuchar tráfico en crudo en el puerto 53 (DNS) en busca de túneles encubiertos o balizas de Comando y Control (C2) (Mitre T1040).

## 🚀 Características Principales

*   **SOAR Integrado:** Bloqueo físico de IPs maliciosas inyectando reglas de caída (Drop) directamente en el Firewall nativo de Windows (`netsh advfirewall`).
*   **Inteligencia de Amenazas (CTI):** Enriquecimiento de IPs en tiempo real integrando la API v3 de VirusTotal de forma segura.
*   **Web Dashboard Seguro:** Interfaz SPA servida sobre **TLS 1.3** estricto, mitigación CSRF nativa y autenticación mediante tokens criptográficos efímeros o estáticos.

---

## 🛠️ Prerrequisitos e Instalación

1. Instalar [Go (Golang)](https://go.dev/dl/).
2. Instalar Wireshark y el motor de red Npcap ejecutando como Administrador:
   ```bash
   winget install WiresharkFoundation.Wireshark
Clonar este repositorio:

Bash
git clone [https://github.com/tolotelin99/tr3yes.git](https://github.com/tolotelin99/tr3yes.git)
cd tr3yes
⚙️ Configuración (Variables de Entorno)
Define las siguientes variables en tu terminal de Git Bash antes de arrancar:

Bash
# [OBLIGATORIO] API Key de VirusTotal para el motor SOAR
export VT_API_KEY="tu_api_key_aqui"

# [OPCIONAL] Interfaz de red a auditar (Ej. 1, 5, etc.)
export TR3YES_IFACE="5"

# [OPCIONAL] Token estático de acceso (Si se omite, se genera uno efímero en consola)
export TR3YES_TOKEN="mi_token_secreto_123"
💻 Uso
Ejecuta el servidor con privilegios de Administrador:

Bash
go run cmd/core/main.go
