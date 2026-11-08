# TR3YES — Tactical Operations Center (SOC/EDR Local)

TR3YES es un motor ligero de Centro de Operaciones de Seguridad (SOC) y Detección y Respuesta en Endpoints (EDR) desarrollado en Go. Diseñado para su despliegue nativo en entornos Windows, proporciona telemetría de red en tiempo real, Inspección Profunda de Paquetes (DPI) y capacidades integradas de SOAR (Orquestación, Automatización y Respuesta de Seguridad) sin depender de agentes comerciales pesados.

## 🏗️ Arquitectura: El Motor de Triple Sensor

Las operaciones del núcleo de TR3YES se ejecutan en rutinas concurrentes de Go que alimentan un registro de auditoría forense unificado (`tr3yes_splunk_audit.json`), capturando telemetría en tiempo real a través de tres sensores de inspección independientes:

1. **Sensor basado en Host (HIDS):** Analiza las tablas de sockets del kernel mediante utilidades nativas del SO (`netstat`) para detectar conexiones TCP establecidas, realizando búsquedas inversas de DNS e identificando vectores de exfiltración saliente (MITRE ATT&CK: T1049).
2. **Inspector TLS/SNI (TSHARK):** Intercepta tráfico cifrado durante la fase inicial del Handshake TLS 1.2/1.3, extrayendo atributos de Indicación de Nombre de Servidor (SNI) para revelar dominios de destino sin romper el cifrado SSL/TLS (MITRE ATT&CK: T1071.001).
3. **Captura de Paquetes en Crudo (TCPDUMP / BPF):** Utiliza sockets de Filtro de Paquetes de Berkeley (BPF) a través de Npcap/Wireshark para monitorear tráfico DNS en crudo (Puerto 53) en busca de túneles encubiertos o balizas de Comando y Control (C2) (MITRE ATT&CK: T1040).

## 🚀 Capacidades Principales

- **Automatización SOAR Nativa:** Contención automatizada mediante la inyección de reglas de firewall en vivo (`netsh advfirewall`), aplicando instantáneamente reglas de bloqueo de entrada/salida en endpoints maliciosos.
- **Inteligencia de Amenazas (CTI):** Enriquecimiento de direcciones IP en tiempo real aprovechando la API REST de VirusTotal v3.
- **Panel Táctico Seguro:** Aplicación de una sola página (SPA) moderna servida sobre TLS 1.3 estricto, equipada con mitigación nativa de CSRF, endurecimiento de sesiones y validación de tokens criptográficos.

## 🛠️ Prerrequisitos e Instalación

1. Go (Golang) (v1.22 o superior)
2. Wireshark y Npcap (Asegúrate de habilitar el modo compatible con la API WinPcap durante la instalación).

Clona e inicializa el repositorio:

```bash
git clone [https://github.com/tolotelin99/tr3yes.git](https://github.com/tolotelin99/tr3yes.git)
cd tr3yes
⚙️ Configuración y Variables de Entorno
Configura los parámetros de ejecución requeridos en tu terminal antes de iniciar:

Bash
# [OBLIGATORIO] Clave de API de VirusTotal para enriquecimiento CTI e inteligencia SOAR
export VT_API_KEY="tu_clave_de_virustotal_aqui"

# [OPCIONAL] Índice de la interfaz de red a auditar (ej. 1, 5)
export TR3YES_IFACE="5"

# [OPCIONAL] Token de autenticación estática (si se omite, se genera un token efímero en consola)
export TR3YES_TOKEN="token_de_acceso_seguro_123"
💻 Ejecución
Ejecuta el servidor SOC con privilegios administrativos elevados:

Bash
go run cmd/core/main.go
Accede a la interfaz táctica segura en tu navegador en:

https://127.0.0.1:8443/

📄 Licencia
Distribuido bajo la Licencia MIT. Consulta LICENSE para más información.
