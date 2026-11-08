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

const loginHTML = `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>tr3yes — Login SOC Corporativo</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
        body { background: #050811; color: #00ff66; font-family: 'Share Tech Mono', monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; text-shadow: 0 0 4px rgba(0,255,102,0.3); }
        .login-box { background: #0a0f1d; border: 1px solid #00ff66; padding: 30px; border-radius: 4px; width: 400px; box-shadow: 0 0 20px rgba(0,255,102,0.15); }
        h2 { color: #00ff66; margin-bottom: 10px; font-size: 18px; text-align: center; }
        .sub { color: #38bdf8; font-size: 12px; text-align: center; margin-bottom: 20px; }
        input { width: 100%; background: #050811; border: 1px solid #00ff66; color: #00ff66; padding: 10px; border-radius: 2px; margin-bottom: 15px; box-sizing: border-box; font-family: inherit; font-size: 14px; outline: none; }
        button { width: 100%; background: #00ff66; color: #050811; border: none; padding: 10px; border-radius: 2px; cursor: pointer; font-weight: bold; font-family: inherit; font-size: 14px; text-transform: uppercase; letter-spacing: 1px; }
        button:hover { background: #38bdf8; color: #050811; box-shadow: 0 0 10px #38bdf8; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>[tr3yes-soc ~]# auth</h2>
        <div class="sub">-- TRIPLE SENSOR ACTIVO --</div>
        <form method="POST" action="/login">
            <input type="password" name="token" placeholder="ENTER ACCESS TOKEN..." required autofocus>
            <button type="submit">EXECUTE LOGIN</button>
        </form>
    </div>
</body>
</html>`

const indexHTML = `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="csrf-token" content="{{CSRF_TOKEN}}">
    <title>tr3yes — Tactical Operations Center</title>
    <link rel="stylesheet" href="/ui.css">
</head>
<body id="soc-body">
    <header class="topbar">
        <div>
            <pre class="ascii-banner">
████████╗██████╗ ██████╗ ██╗   ██╗███████╗███████╗
╚══██╔══╝██╔══██╗╚════██╗╚██╗ ██╔╝██╔════╝██╔════╝
   ██║   ██████╔╝ █████╔╝ ╚████╔╝ █████╗  ███████╗
   ██║   ██╔══██╗ ╚═══██╗  ╚██╔╝  ██╔══╝  ╚════██║
   ██║   ██║  ██║██████╔╝   ██║   ███████╗███████║
   ╚═╝   ╚═╝  ╚═╝╚═════╝    ╚═╝   ╚══════╝╚══════╝
            </pre>
            <p class="subtitle">> TTY_SESSION: SECURE // SENSORS: HIDS, TSHARK, TCPDUMP(BPF)</p>
        </div>
        <div class="topbar-actions">
            <button class="btn" id="btn-toggle-engine" onclick="toggleEngine()" style="background: #064e3b; color: #34d399; border-color: #059669;">[ PAUSE ]</button>
            <button class="btn" onclick="exportEvidence()" style="background: #312e81; color: #818cf8; border-color: #4f46e5;">[ 📥 EXPORT_ALL ]</button>
            <button class="btn" onclick="togglePanicMode()" style="background: #7f1d1d; color: #fca5a5; border-color: #dc2626;" id="btn-panic">[ 🚨 RED_ALERT ]</button>
            <div class="badge-live" id="engine-status">[● SENSORS LIVE]</div>
        </div>
    </header>

    <section class="kpi-grid">
        <div class="kpi-card total"><span class="kpi-title">NET_EVENTS</span><span class="kpi-value" id="count-total">0</span></div>
        <div class="kpi-card tcpdump"><span class="kpi-title">TCPDUMP_RAW</span><span class="kpi-value" id="count-tcpdump">0</span></div>
        <div class="kpi-card tshark"><span class="kpi-title">TSHARK_TLS</span><span class="kpi-value" id="count-tshark">0</span></div>
        <div class="kpi-card host"><span class="kpi-title">HOST_HIDS</span><span class="kpi-value" id="count-host">0</span></div>
    </section>

    <section class="controls">
        <div style="display: flex; gap: 8px; flex-wrap: wrap; flex: 1;">
            <button class="btn active" data-filter="ALL">ALL</button>
            <button class="btn" data-filter="Host-Sensor" style="border-color: #34d399;">HOST</button>
            <button class="btn" data-filter="Tshark" style="border-color: #38bdf8;">TSHARK</button>
            <button class="btn" data-filter="Tcpdump" style="border-color: #818cf8;">TCPDUMP</button>
            <button class="btn" data-filter="Nuevo" style="border-color: #fbbf24;">NUEVOS</button>
            <button class="btn" data-filter="Falso Positivo" style="border-color: #94a3b8;">FP</button>
            <input type="text" id="search-box" placeholder="grep --filter (IP, estado, MITRE ID)...">
        </div>
        <button class="btn" onclick="clearAllEvents()" style="background: #450a0a; color: #fca5a5; border-color: #991b1b;">[ 🗑️ PURGE ]</button>
    </section>

    <section class="table-wrap">
        <table>
            <thead>
                <tr>
                    <th>#</th>
                    <th>TIMESTAMP</th>
                    <th>SENSOR</th>
                    <th>EVENT_PAYLOAD</th>
                    <th>MITRE_ATT&CK</th>
                    <th>STATUS</th>
                    <th>CLI_ACTIONS</th>
                </tr>
            </thead>
            <tbody id="events-body">
                <tr><td colspan="7" style="text-align: center; color: #38bdf8; padding: 20px;">INICIALIZANDO TRIPLE SENSOR DE RED...</td></tr>
            </tbody>
        </table>
    </section>

    <div id="modal-detail" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal()">&times;</span>
            <h2 style="color: #00ff66; margin-bottom: 8px; font-size: 15px; text-transform: uppercase;">[ REAL_TIME_FORENSIC_CONSOLE ]</h2>
            
            <div style="font-size: 10.5px; color: #38bdf8; margin-bottom: 4px; font-weight: bold;">RAW PAYLOAD JSON:</div>
            <pre id="modal-text" style="background: #030712; padding: 8px; border-radius: 2px; border: 1px solid #1e293b; color: #00ff66; overflow-x: auto; font-size: 11px; max-height: 120px; margin-bottom: 10px;"></pre>
            
            <div style="font-size: 10.5px; color: #fbbf24; margin-bottom: 4px; font-weight: bold;">IP INTEL & ORIGIN ANALYSIS:</div>
            <div id="modal-ip-intel" style="background: #030712; padding: 8px; border-radius: 2px; border: 1px solid #1e293b; color: #f8fafc; font-size: 11px; margin-bottom: 10px; line-height: 1.3;"></div>

            <div style="font-size: 10.5px; color: #34d399; margin-bottom: 4px; font-weight: bold;">MITRE ATT&CK PLAYBOOK & REMEDIATION:</div>
            <div id="modal-mitre-guide" style="background: #030712; padding: 8px; border-radius: 2px; border: 1px solid #1e293b; color: #e2e8f0; font-size: 11px; margin-bottom: 12px; line-height: 1.3;"></div>

            <div style="border-top: 1px dashed #1e293b; padding-top: 12px; display: flex; gap: 8px; flex-wrap: wrap; justify-content: space-between; align-items: center;">
                <div style="display: flex; gap: 6px; flex-wrap: wrap;">
                    <button class="btn" onclick="soarEnrichIP()" style="background: #0c4a6e; color: #38bdf8; border-color: #0284c7;">[ 🔍 VIRUSTOTAL INTEL ]</button>
                    <button class="btn" onclick="soarBlockIP()" style="background: #450a0a; color: #fca5a5; border-color: #b91c1c;">[ 🚫 SOAR: NATIVE FIREWALL BLOCK ]</button>
                </div>
                <button class="btn" onclick="exportSingleEvent()" style="background: #312e81; color: #818cf8; border-color: #4f46e5;">[ 📥 EXPORT_LOG ]</button>
            </div>
            <div id="soar-status-msg" style="margin-top: 8px; font-size: 11px; color: #00ff66; min-height: 15px;"></div>
        </div>
    </div>
    <script src="/app.js"></script>
</body>
</html>`

const uiCSS = `
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #030712; color: #38bdf8; font-family: 'Share Tech Mono', monospace; padding: 20px; transition: background 0.3s ease; text-shadow: 0 0 3px rgba(56, 189, 248, 0.25); }
body.panic { background: #450a0a !important; color: #fca5a5 !important; text-shadow: 0 0 5px rgba(252, 165, 165, 0.4) !important; }
.topbar { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px dashed #1e293b; padding-bottom: 16px; margin-bottom: 24px; flex-wrap: wrap; gap: 12px; }
.topbar-actions { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }
.ascii-banner { color: #00ff66; font-size: 8px; line-height: 9px; font-weight: bold; letter-spacing: 1px; margin-bottom: 6px; text-shadow: 0 0 8px rgba(0, 255, 102, 0.5); }
.subtitle { color: #94a3b8; font-size: 11px; letter-spacing: 1px; text-transform: uppercase; }
.badge-live { background: rgba(0, 255, 102, 0.1); color: #00ff66; border: 1px solid #00ff66; padding: 5px 10px; border-radius: 2px; font-weight: bold; font-size: 11px; text-shadow: 0 0 5px #00ff66; }
.kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 24px; }
.kpi-card { background: #0a0f1d; border: 1px solid #1e293b; border-left: 4px solid #00ff66; padding: 14px; border-radius: 2px; box-shadow: inset 0 0 10px rgba(0,0,0,0.5); }
.kpi-card.tcpdump { border-left-color: #818cf8; }
.kpi-card.tshark { border-left-color: #38bdf8; }
.kpi-card.host { border-left-color: #34d399; }
.kpi-title { display: block; font-size: 10px; color: #64748b; margin-bottom: 6px; text-transform: uppercase; letter-spacing: 1px; }
.kpi-value { font-size: 24px; font-weight: bold; color: #f8fafc; text-shadow: 0 0 6px rgba(255,255,255,0.3); }
.controls { display: flex; gap: 8px; margin-bottom: 18px; align-items: center; flex-wrap: wrap; }
.btn { background: #0a0f1d; color: #38bdf8; border: 1px solid #334155; padding: 6px 10px; border-radius: 2px; cursor: pointer; font-family: inherit; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }
.btn.active, .btn:hover { background: #38bdf8; color: #030712; border-color: #38bdf8; box-shadow: 0 0 8px rgba(56, 189, 248, 0.5); }
#search-box { flex: 1; min-width: 220px; background: #0a0f1d; color: #00ff66; border: 1px solid #334155; padding: 6px 10px; border-radius: 2px; font-family: inherit; font-size: 12px; outline: none; }
#search-box:focus { border-color: #00ff66; box-shadow: 0 0 8px rgba(0, 255, 102, 0.3); }
.table-wrap { background: #0a0f1d; border: 1px solid #1e293b; border-radius: 2px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.4); }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { background: #0f172a; color: #94a3b8; text-align: left; padding: 10px 12px; text-transform: uppercase; font-size: 11px; border-bottom: 1px solid #1e293b; letter-spacing: 1px; }
td { padding: 9px 12px; border-bottom: 1px solid #0f172a; }
tr:hover { background: #0f172a; }
.tag { padding: 2px 5px; border-radius: 2px; font-weight: bold; font-size: 10px; display: inline-block; text-transform: uppercase; }
.tag-Host-Sensor { background: rgba(52, 211, 153, 0.1); color: #34d399; border: 1px solid #059669; }
.tag-Tshark { background: rgba(56, 189, 248, 0.1); color: #38bdf8; border: 1px solid #0284c7; }
.tag-Tcpdump { background: rgba(129, 140, 248, 0.1); color: #818cf8; border: 1px solid #4f46e5; }
.mitre-badge { background: rgba(244, 63, 94, 0.1); color: #fb7185; border: 1px solid #e11d48; padding: 2px 5px; border-radius: 2px; font-weight: bold; font-size: 10px; }
.status-nuevo { color: #fbbf24; font-weight: bold; text-transform: uppercase; }
.status-fp { color: #64748b; text-decoration: line-through; text-transform: uppercase; }
.status-mitigado { color: #34d399; font-weight: bold; text-transform: uppercase; }
.status-bloqueado { color: #f87171; font-weight: bold; text-transform: uppercase; }
.action-btn { background: #1e293b; color: #f8fafc; border: 1px solid #334155; padding: 4px 7px; border-radius: 2px; cursor: pointer; font-size: 10px; margin-right: 2px; font-family: inherit; font-weight: bold; text-transform: uppercase; }
.action-btn:hover { background: #334155; border-color: #94a3b8; }
.action-btn.fp { background: #451a03; color: #fbbf24; border-color: #b45309; }
.action-btn.mit { background: #064e3b; color: #34d399; border-color: #047857; }
.action-btn.del { background: #450a0a; color: #fca5a5; border-color: #b91c1c; }
.modal { display: none; position: fixed; z-index: 100; left: 0; top: 0; width: 100%; height: 100%; background: rgba(3,7,18,0.85); justify-content: center; align-items: center; }
.modal-content { background: #0a0f1d; border: 1px solid #00ff66; padding: 20px; border-radius: 2px; width: 720px; max-width: 90%; box-shadow: 0 0 25px rgba(0,255,102,0.2); }
.close { color: #94a3b8; float: right; font-size: 20px; font-weight: bold; cursor: pointer; font-family: monospace; }
.close:hover { color: #00ff66; }
`

const appJS = `
let currentFilter = 'ALL';
let allEvents = [];
let currentEvent = null;
let enginePaused = false;
let panicMode = false;

const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

async function secureFetch(url, options = {}) {
    options.headers = options.headers || {};
    options.headers['X-CSRF-Token'] = csrfToken;
    return fetch(url, options);
}

const mitreKnowledgeBase = {
    "T1049": { name: "System Network Connections Discovery", mitigation: "Analizar el puerto destino y la IP para validar si corresponde a tráfico legítimo. Bloquear si es sospechoso." },
    "T1071.001": { name: "Application Layer Protocol: Web Protocols", mitigation: "Analizar los dominios SNI capturados por Tshark para identificar C2 (Comando y Control)." },
    "T1040": { name: "Network Sniffing (Raw Packets)", mitigation: "Verificar si las peticiones DNS (Puerto 53) detectadas por Tcpdump corresponden a túneles de exfiltración de datos." }
};

document.querySelectorAll('.btn[data-filter]').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.btn[data-filter]').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentFilter = btn.getAttribute('data-filter');
        renderTable();
    });
});

document.getElementById('search-box').addEventListener('input', renderTable);

function renderTable() {
    const query = document.getElementById('search-box').value.toLowerCase().trim();
    const tbody = document.getElementById('events-body');
    tbody.textContent = '';

    if (allEvents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #fbbf24; padding: 20px;">[!] SENSORES ACTIVOS. ESPERANDO TRÁFICO REAL...</td></tr>';
        document.getElementById('count-total').textContent = 0; document.getElementById('count-tcpdump').textContent = 0; document.getElementById('count-tshark').textContent = 0; document.getElementById('count-host').textContent = 0; return;
    }

    let cHost = 0, cTshark = 0, cTcpdump = 0;
    allEvents.forEach(ev => {
        if (ev.source === 'Host-Sensor') cHost++;
        if (ev.source === 'Tshark') cTshark++;
        if (ev.source === 'Tcpdump') cTcpdump++;
    });

    document.getElementById('count-total').textContent = allEvents.length;
    document.getElementById('count-host').textContent = cHost;
    document.getElementById('count-tshark').textContent = cTshark;
    document.getElementById('count-tcpdump').textContent = cTcpdump;

    const filtered = allEvents.slice().reverse().filter(ev => {
        let matchFilter = true;
        if (currentFilter === 'Host-Sensor' || currentFilter === 'Tshark' || currentFilter === 'Tcpdump') { matchFilter = (ev.source === currentFilter); } 
        else if (currentFilter === 'Nuevo' || currentFilter === 'Falso Positivo') { matchFilter = (ev.status === currentFilter); }
        const text = (ev.timestamp + ' ' + ev.source + ' ' + ev.event_type + ' ' + ev.mitre_id + ' ' + ev.description).toLowerCase();
        return matchFilter && text.includes(query);
    });

    if (filtered.length === 0) { tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 20px;">[!] NO GREP MATCH FOUND.</td></tr>'; return; }

    filtered.slice(0, 100).forEach(ev => {
        const tr = document.createElement('tr');
        
        const tdNum = document.createElement('td');
        tdNum.textContent = allEvents.indexOf(ev) + 1;
        tdNum.style.color = '#64748b';
        tdNum.style.fontWeight = 'bold';

        const tdTime = document.createElement('td'); 
        const dateObj = new Date(ev.timestamp);
        tdTime.textContent = dateObj.toLocaleString('es-AR', { 
            day: '2-digit', month: '2-digit', year: 'numeric', 
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false 
        });

        const tdSrc = document.createElement('td'); const spanSrc = document.createElement('span'); spanSrc.className = 'tag tag-' + ev.source; spanSrc.textContent = ev.source; tdSrc.appendChild(spanSrc);
        const tdType = document.createElement('td'); tdType.textContent = ev.event_type;
        const tdMitre = document.createElement('td'); const spanMitre = document.createElement('span'); spanMitre.className = 'mitre-badge'; spanMitre.textContent = ev.mitre_id; tdMitre.appendChild(spanMitre);

        const tdStatus = document.createElement('td');
        const spanStatus = document.createElement('span');
        let statusClass = 'status-nuevo';
        if (ev.status === 'Falso Positivo') statusClass = 'status-fp';
        if (ev.status === 'Mitigado') statusClass = 'status-mitigado';
        if (ev.status === 'SOAR_BLOQUEADO') statusClass = 'status-bloqueado';
        spanStatus.className = statusClass; spanStatus.textContent = ev.status || 'Nuevo'; tdStatus.appendChild(spanStatus);

        const tdActions = document.createElement('td');
        const btnDetail = document.createElement('button'); btnDetail.className = 'action-btn'; btnDetail.textContent = 'INSPECT'; btnDetail.onclick = () => showDetail(ev);
        const btnFP = document.createElement('button'); btnFP.className = 'action-btn fp'; btnFP.textContent = 'FP'; btnFP.onclick = () => updateEventStatus(ev.id, 'Falso Positivo');
        const btnMit = document.createElement('button'); btnMit.className = 'action-btn mit'; btnMit.textContent = 'MITIGATE'; btnMit.onclick = () => updateEventStatus(ev.id, 'Mitigado');
        const btnDel = document.createElement('button'); btnDel.className = 'action-btn del'; btnDel.textContent = 'DROP'; btnDel.onclick = () => deleteEvent(ev.id);

        tdActions.append(btnDetail, btnFP, btnMit, btnDel);
        tr.append(tdNum, tdTime, tdSrc, tdType, tdMitre, tdStatus, tdActions);
        tbody.appendChild(tr);
    });
}

function analyzeIPsInText(text) {
    const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
    const matches = text.match(ipRegex);
    if (!matches || matches.length === 0) { return "<span>[i] Verificando red / Sin IP directa.</span>"; }

    let intelHtml = "";
    matches.forEach(ip => {
        let type = "Pública (Externa / Internet)"; let color = "#fb7185";
        if (ip.startsWith("127.") || ip === "0.0.0.0") { type = "Loopback (Tráfico de tu misma PC)"; color = "#00ff66"; } 
        else if (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.match(/^172\.(1[6-9]|2\d|3[0-1])\./)) { type = "Red Privada (LAN Local / Router)"; color = "#38bdf8"; }
        intelHtml += '<div style="margin-bottom: 4px;"><b>IP:</b> <code style="color:' + color + ';" id="target-ip">' + ip + '</code> -> ' + type + '</div>';
    });
    return intelHtml;
}

function showDetail(ev) {
    currentEvent = ev;
    const modal = document.getElementById('modal-detail');
    const text = document.getElementById('modal-text');
    document.getElementById('soar-status-msg').textContent = '';
    text.textContent = JSON.stringify(ev, null, 2);
    document.getElementById('modal-ip-intel').innerHTML = analyzeIPsInText(ev.description);

    let mitreCodeKey = Object.keys(mitreKnowledgeBase).find(k => ev.mitre_id.includes(k));
    if (mitreCodeKey) { document.getElementById('modal-mitre-guide').innerHTML = '<b>Técnica:</b> ' + mitreKnowledgeBase[mitreCodeKey].name + '<br><b>Defensa:</b> ' + mitreKnowledgeBase[mitreCodeKey].mitigation; } 
    else { document.getElementById('modal-mitre-guide').innerHTML = '<i>[i] Sin playbook específico en base local. Analizar payload manualmente.</i>'; }
    modal.style.display = 'flex';
}

function closeModal() { document.getElementById('modal-detail').style.display = 'none'; }

async function soarEnrichIP() {
    const statusMsg = document.getElementById('soar-status-msg');
    const ipElem = document.getElementById('target-ip');
    if (!ipElem) { alert("No se detectó ninguna IP válida para consultar."); return; }
    
    const targetIP = ipElem.textContent;
    statusMsg.style.color = '#38bdf8';
    statusMsg.textContent = '[⏳ SOAR] Consultando API de VirusTotal para ' + targetIP + '...';

    try {
        const res = await secureFetch('/api/soar/enrich', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip: targetIP }) });
        if (res.ok) {
            const data = await res.json();
            if (data.error) { statusMsg.style.color = '#fbbf24'; statusMsg.textContent = '[!] ' + data.error; } 
            else { statusMsg.style.color = parseInt(data.malicious) > 0 ? '#f87171' : '#00ff66'; statusMsg.innerHTML = data.message + ' <a href="https://www.virustotal.com/gui/ip-address/' + targetIP + '" target="_blank" style="color:#38bdf8; text-decoration:underline;">[Ver Reporte]</a>'; }
        } else { statusMsg.style.color = '#f87171'; statusMsg.textContent = '[!] Error HTTP al conectar con el backend SOAR.'; }
    } catch (e) { statusMsg.style.color = '#f87171'; statusMsg.textContent = '[!] Fallo de red interno.'; }
}

async function soarBlockIP() {
    const ipElem = document.getElementById('target-ip');
    if (!ipElem) { alert("No se detectó ninguna IP para bloquear."); return; }
    const ipToBlock = ipElem.textContent;
    if (!confirm('[SOAR] ¿Bloquear ' + ipToBlock + ' cortando su acceso nativo en Windows Firewall?')) return;
    
    const statusMsg = document.getElementById('soar-status-msg');
    statusMsg.style.color = '#38bdf8';
    statusMsg.textContent = '[⏳ SOAR] Creando regla Drop en Windows Firewall...';
    
    const res = await secureFetch('/api/soar/block-ip', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip: ipToBlock, id: currentEvent.id }) });
    if (res.ok) {
        statusMsg.style.color = '#f87171';
        statusMsg.textContent = '[🚫 SOAR] IP ' + ipToBlock + ' bloqueada nativamente y añadida a la Blacklist HIDS.';
        setTimeout(() => { closeModal(); fetchEvents(); }, 1800);
    } else { statusMsg.style.color = '#fbbf24'; statusMsg.textContent = '[!] Error en el backend. Revisa la terminal.'; }
}

async function updateEventStatus(id, status) { await secureFetch('/api/event/status', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id, status }) }); fetchEvents(); }
async function deleteEvent(id) { await secureFetch('/api/event/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) }); fetchEvents(); }
async function clearAllEvents() { if (!confirm('[?] PURGAR BASE DE DATOS FORENSE?')) return; await secureFetch('/api/events/clear', { method: 'POST' }); fetchEvents(); }
function exportSingleEvent() { if (!currentEvent) return; const downloadAnchor = document.createElement('a'); downloadAnchor.setAttribute("href", "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentEvent, null, 2))); downloadAnchor.setAttribute("download", "tr3yes_log_" + currentEvent.id + ".json"); document.body.appendChild(downloadAnchor); downloadAnchor.click(); downloadAnchor.remove(); }
function exportEvidence() { const downloadAnchor = document.createElement('a'); downloadAnchor.setAttribute("href", "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(allEvents, null, 2))); downloadAnchor.setAttribute("download", "tr3yes_forensic_dump_" + Date.now() + ".json"); document.body.appendChild(downloadAnchor); downloadAnchor.click(); downloadAnchor.remove(); }
function togglePanicMode() { panicMode = !panicMode; const body = document.getElementById('soc-body'); const btn = document.getElementById('btn-panic'); if (panicMode) { body.classList.add('panic'); btn.textContent = '[ 🚨 DEFCON_1 ]'; } else { body.classList.remove('panic'); btn.textContent = '[ 🚨 RED_ALERT ]'; } }
async function toggleEngine() { const res = await secureFetch('/api/engine/toggle', { method: 'POST' }); const data = await res.json(); enginePaused = data.paused; const btn = document.getElementById('btn-toggle-engine'); const badge = document.getElementById('engine-status'); if (enginePaused) { btn.textContent = '[ RESUME ]'; badge.textContent = '[● SENSORS PAUSED]'; } else { btn.textContent = '[ PAUSE ]'; badge.textContent = '[● SENSORS LIVE]'; } }
async function fetchEvents() { if (enginePaused) return; try { const res = await secureFetch('/api/events'); if (res.status === 401) { window.location.href = '/login'; return; } if (res.ok) { allEvents = await res.json(); renderTable(); } } catch (e) { console.error("Error fetching events:", e); } }

fetchEvents();
setInterval(fetchEvents, 3000);
`

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

func procesarLineaConexionRed(dbPath string, linea string) {
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
		w.Write([]byte(fmt.Sprintf(`<body style="background:#050811;color:#f87171;font-family:monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;"><div style="background:#0a0f1d;border:1px solid #dc2626;padding:30px;border-radius:4px;text-align:center;"><h2>[!] BLOQUEO DE SEGURIDAD (BRUTE FORCE)</h2><p>Demasiados intentos fallidos. IP bloqueada temporalmente. Inténtalo en %ds.</p><br><a href="/login" style="color:#38bdf8;">Volver al Login</a></div></body>`, tiempoRestante)))
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
	w.Write([]byte(loginHTML))
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	aplicarCabeceras(w, r)
	if !validarSesion(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	w.Header().Set(headerContentType, contentTypeHTML)
	htmlFinal := strings.Replace(indexHTML, "{{CSRF_TOKEN}}", csrfToken, 1)
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
		w.Write([]byte(uiCSS))
	})
	http.HandleFunc("/app.js", func(w http.ResponseWriter, r *http.Request) {
		aplicarCabeceras(w, r)
		w.Header().Set(headerContentType, "application/javascript; charset=utf-8")
		w.Write([]byte(appJS))
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
	fmt.Println("[+] TR3YES SOC (Triple Sensor / Interfaz Hardcodeada)")
	fmt.Println("[+] URL DE ACCESO: https://127.0.0.1:8443/")
	if os.Getenv("TR3YES_TOKEN") != "" {
		fmt.Println("[+] TOKEN CARGADO DESDE VARIABLE DE ENTORNO")
	} else {
		fmt.Printf("[+] TOKEN EFÍMERO EN RAM (COPIAR): %s\n", serverToken)
	}
	fmt.Println("==========================================================")
	log.Fatal(server.ListenAndServeTLS("", ""))
}
