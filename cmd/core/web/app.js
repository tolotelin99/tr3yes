let currentFilter = 'ALL';
let allEvents = [];
let currentEvent = null;
let enginePaused = false;
let panicMode = false;

const metaCsrf = document.querySelector('meta[name="csrf-token"]');
const csrfToken = metaCsrf ? metaCsrf.getAttribute('content') : '';

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
        currentFilter = btn.dataset.filter || 'ALL';
        renderTable();
    });
});

const searchBox = document.getElementById('search-box');
if (searchBox) {
    searchBox.addEventListener('input', renderTable);
}

function renderTable() {
    const queryInput = document.getElementById('search-box');
    const query = queryInput ? queryInput.value.toLowerCase().trim() : '';
    const tbody = document.getElementById('events-body');
    if (!tbody) return;
    tbody.textContent = '';

    if (allEvents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #fbbf24; padding: 20px;">[!] SENSORES ACTIVOS. ESPERANDO TRÁFICO REAL...</td></tr>';
        const ctTotal = document.getElementById('count-total');
        const ctTcp = document.getElementById('count-tcpdump');
        const ctTshark = document.getElementById('count-tshark');
        const ctHost = document.getElementById('count-host');
        if (ctTotal) ctTotal.textContent = '0';
        if (ctTcp) ctTcp.textContent = '0';
        if (ctTshark) ctTshark.textContent = '0';
        if (ctHost) ctHost.textContent = '0';
        return;
    }

    let cHost = 0, cTshark = 0, cTcpdump = 0;
    allEvents.forEach(ev => {
        if (ev.source === 'Host-Sensor') cHost++;
        if (ev.source === 'Tshark') cTshark++;
        if (ev.source === 'Tcpdump') cTcpdump++;
    });

    const ctTotal = document.getElementById('count-total');
    const ctHostElem = document.getElementById('count-host');
    const ctTsharkElem = document.getElementById('count-tshark');
    const ctTcpElem = document.getElementById('count-tcpdump');
    if (ctTotal) ctTotal.textContent = String(allEvents.length);
    if (ctHostElem) ctHostElem.textContent = String(cHost);
    if (ctTsharkElem) ctTsharkElem.textContent = String(cTshark);
    if (ctTcpElem) ctTcpElem.textContent = String(cTcpdump);

    const filtered = allEvents.slice().reverse().filter(ev => {
        let matchFilter = true;
        if (currentFilter === 'Host-Sensor' || currentFilter === 'Tshark' || currentFilter === 'Tcpdump') { 
            matchFilter = (ev.source === currentFilter); 
        } else if (currentFilter === 'Nuevo' || currentFilter === 'Falso Positivo') { 
            matchFilter = (ev.status === currentFilter); 
        }
        const text = (ev.timestamp + ' ' + ev.source + ' ' + ev.event_type + ' ' + ev.mitre_id + ' ' + ev.description).toLowerCase();
        return matchFilter && text.includes(query);
    });

    if (filtered.length === 0) { 
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #64748b; padding: 20px;">[!] NO GREP MATCH FOUND.</td></tr>'; 
        return; 
    }

    filtered.slice(0, 100).forEach(ev => {
        const tr = document.createElement('tr');
        
        const tdNum = document.createElement('td');
        tdNum.textContent = String(allEvents.indexOf(ev) + 1);
        tdNum.style.color = '#64748b';
        tdNum.style.fontWeight = 'bold';

        const tdTime = document.createElement('td'); 
        const dateObj = new Date(ev.timestamp);
        tdTime.textContent = dateObj.toLocaleString('es-AR', { 
            day: '2-digit', month: '2-digit', year: 'numeric', 
            hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false 
        });

        const tdSrc = document.createElement('td'); 
        const spanSrc = document.createElement('span'); 
        spanSrc.className = 'tag tag-' + ev.source; 
        spanSrc.textContent = ev.source; 
        tdSrc.appendChild(spanSrc);

        const tdType = document.createElement('td'); 
        tdType.textContent = ev.event_type;

        const tdMitre = document.createElement('td'); 
        const spanMitre = document.createElement('span'); 
        spanMitre.className = 'mitre-badge'; 
        spanMitre.textContent = ev.mitre_id; 
        tdMitre.appendChild(spanMitre);

        const tdStatus = document.createElement('td');
        const spanStatus = document.createElement('span');
        let statusClass = 'status-nuevo';
        if (ev.status === 'Falso Positivo') statusClass = 'status-fp';
        if (ev.status === 'Mitigado') statusClass = 'status-mitigado';
        if (ev.status === 'SOAR_BLOQUEADO') statusClass = 'status-bloqueado';
        spanStatus.className = statusClass; 
        spanStatus.textContent = ev.status || 'Nuevo'; 
        tdStatus.appendChild(spanStatus);

        const tdActions = document.createElement('td');
        const btnDetail = document.createElement('button'); 
        btnDetail.className = 'action-btn'; 
        btnDetail.textContent = 'INSPECT'; 
        btnDetail.onclick = () => showDetail(ev);

        const btnFP = document.createElement('button'); 
        btnFP.className = 'action-btn fp'; 
        btnFP.textContent = 'FP'; 
        btnFP.onclick = () => { void updateEventStatus(ev.id, 'Falso Positivo'); };

        const btnMit = document.createElement('button'); 
        btnMit.className = 'action-btn mit'; 
        btnMit.textContent = 'MITIGATE'; 
        btnMit.onclick = () => { void updateEventStatus(ev.id, 'Mitigado'); };

        const btnDel = document.createElement('button'); 
        btnDel.className = 'action-btn del'; 
        btnDel.textContent = 'DROP'; 
        btnDel.onclick = () => { void deleteEvent(ev.id); };

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
        let type = "Pública (Externa / Internet)"; 
        let color = "#fb7185";
        if (ip.startsWith("127.") || ip === "0.0.0.0") { 
            type = "Loopback (Tráfico de tu misma PC)"; 
            color = "#00ff66"; 
        } else if (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.match(/^172\.(1[6-9]|2\d|3[0-1])\./)) { 
            type = "Red Privada (LAN Local / Router)"; 
            color = "#38bdf8"; 
        }
        intelHtml += '<div style="margin-bottom: 4px;"><b>IP:</b> <code style="color:' + color + ';" id="target-ip">' + ip + '</code> -> ' + type + '</div>';
    });
    return intelHtml;
}

function showDetail(ev) {
    currentEvent = ev;
    const modal = document.getElementById('modal-detail');
    const text = document.getElementById('modal-text');
    const soarMsg = document.getElementById('soar-status-msg');
    const ipIntel = document.getElementById('modal-ip-intel');
    const mitreGuide = document.getElementById('modal-mitre-guide');
    
    if (soarMsg) soarMsg.textContent = '';
    if (text) text.textContent = JSON.stringify(ev, null, 2);
    if (ipIntel) ipIntel.innerHTML = analyzeIPsInText(ev.description);

    let mitreCodeKey = Object.keys(mitreKnowledgeBase).find(k => ev.mitre_id.includes(k));
    if (mitreGuide) {
        if (mitreCodeKey) { 
            mitreGuide.innerHTML = '<b>Técnica:</b> ' + mitreKnowledgeBase[mitreCodeKey].name + '<br><b>Defensa:</b> ' + mitreKnowledgeBase[mitreCodeKey].mitigation; 
        } else { 
            mitreGuide.innerHTML = '<i>[i] Sin playbook específico en base local. Analizar payload manualmente.</i>'; 
        }
    }
    if (modal) modal.style.display = 'flex';
}

function closeModal() { 
    const modal = document.getElementById('modal-detail');
    if (modal) modal.style.display = 'none'; 
}

async function soarEnrichIP() {
    const statusMsg = document.getElementById('soar-status-msg');
    const ipElem = document.getElementById('target-ip');
    if (!ipElem) { 
        alert("No se detectó ninguna IP válida para consultar."); 
        return; 
    }
    
    const targetIP = ipElem.textContent;
    if (statusMsg) {
        statusMsg.style.color = '#38bdf8';
        statusMsg.textContent = '[⏳ SOAR] Consultando API de VirusTotal para ' + targetIP + '...';
    }

    try {
        const res = await secureFetch('/api/soar/enrich', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip: targetIP }) });
        if (res.ok) {
            const data = await res.json();
            if (statusMsg) {
                if (data.error) { 
                    statusMsg.style.color = '#fbbf24'; 
                    statusMsg.textContent = '[!] ' + data.error; 
                } else { 
                    const maliciousCount = Number.parseInt(String(data.malicious || 0), 10);
                    statusMsg.style.color = maliciousCount > 0 ? '#f87171' : '#00ff66'; 
                    statusMsg.innerHTML = data.message + ' <a href="https://www.virustotal.com/gui/ip-address/' + targetIP + '" target="_blank" style="color:#38bdf8; text-decoration:underline;">[Ver Reporte]</a>'; 
                }
            }
        } else if (statusMsg) { 
            statusMsg.style.color = '#f87171'; 
            statusMsg.textContent = '[!] Error HTTP al conectar con el backend SOAR.'; 
        }
    } catch (e) { 
        if (statusMsg) {
            statusMsg.style.color = '#f87171'; 
            statusMsg.textContent = '[!] Fallo de red interno.'; 
        }
    }
}

async function soarBlockIP() {
    const ipElem = document.getElementById('target-ip');
    if (!ipElem) { 
        alert("No se detectó ninguna IP para bloquear."); 
        return; 
    }
    const ipToBlock = ipElem.textContent;
    if (!confirm('[SOAR] ¿Bloquear ' + ipToBlock + ' cortando su acceso nativo em Windows Firewall?')) return;
    
    const statusMsg = document.getElementById('soar-status-msg');
    if (statusMsg) {
        statusMsg.style.color = '#38bdf8';
        statusMsg.textContent = '[⏳ SOAR] Creando regla Drop en Windows Firewall...';
    }
    
    try {
        const res = await secureFetch('/api/soar/block-ip', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip: ipToBlock, id: currentEvent ? currentEvent.id : '' }) });
        if (res.ok) {
            if (statusMsg) {
                statusMsg.style.color = '#f87171';
                statusMsg.textContent = '[🚫 SOAR] IP ' + ipToBlock + ' bloqueada nativamente y añadida a la Blacklist HIDS.';
            }
            setTimeout(() => { closeModal(); void fetchEvents(); }, 1800);
        } else if (statusMsg) { 
            statusMsg.style.color = '#fbbf24'; 
            statusMsg.textContent = '[!] Error en el backend. Revisa la terminal.'; 
        }
    } catch (err) {
        if (statusMsg) {
            statusMsg.style.color = '#f87171';
            statusMsg.textContent = '[!] Error de conexión al bloquear IP.';
        }
    }
}

async function updateEventStatus(id, status) { 
    try {
        await secureFetch('/api/event/status', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id, status }) }); 
        await fetchEvents(); 
    } catch (err) {
        console.error("Error updating event status:", err);
    }
}

async function deleteEvent(id) { 
    try {
        await secureFetch('/api/event/delete', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id }) }); 
        await fetchEvents(); 
    } catch (err) {
        console.error("Error deleting event:", err);
    }
}

async function clearAllEvents() { 
    if (!confirm('[?] PURGAR BASE DE DATOS FORENSE?')) return; 
    try {
        await secureFetch('/api/events/clear', { method: 'POST' }); 
        await fetchEvents(); 
    } catch (err) {
        console.error("Error clearing events:", err);
    }
}

function exportSingleEvent() { 
    if (!currentEvent) return; 
    const downloadAnchor = document.createElement('a'); 
    downloadAnchor.setAttribute("href", "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(currentEvent, null, 2))); 
    downloadAnchor.setAttribute("download", "tr3yes_log_" + currentEvent.id + ".json"); 
    document.body.appendChild(downloadAnchor); 
    downloadAnchor.click(); 
    downloadAnchor.remove(); 
}

function exportEvidence() { 
    const downloadAnchor = document.createElement('a'); 
    downloadAnchor.setAttribute("href", "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(allEvents, null, 2))); 
    downloadAnchor.setAttribute("download", "tr3yes_forensic_dump_" + Date.now() + ".json"); 
    document.body.appendChild(downloadAnchor); 
    downloadAnchor.click(); 
    downloadAnchor.remove(); 
}

function togglePanicMode() { 
    panicMode = !panicMode; 
    const body = document.getElementById('soc-body'); 
    const btn = document.getElementById('btn-panic'); 
    if (panicMode) { 
        if (body) body.classList.add('panic'); 
        if (btn) btn.textContent = '[ 🚨 DEFCON_1 ]'; 
    } else { 
        if (body) body.classList.remove('panic'); 
        if (btn) btn.textContent = '[ 🚨 RED_ALERT ]'; 
    } 
}

async function toggleEngine() { 
    try {
        const res = await secureFetch('/api/engine/toggle', { method: 'POST' }); 
        const data = await res.json(); 
        enginePaused = data.paused; 
        const btn = document.getElementById('btn-toggle-engine'); 
        const badge = document.getElementById('engine-status'); 
        if (enginePaused) { 
            if (btn) btn.textContent = '[ RESUME ]'; 
            if (badge) badge.textContent = '[● SENSORS PAUSED]'; 
        } else { 
            if (btn) btn.textContent = '[ PAUSE ]'; 
            if (badge) badge.textContent = '[● SENSORS LIVE]'; 
        } 
    } catch (err) {
        console.error("Error toggling engine:", err);
    }
}

async function fetchEvents() { 
    if (enginePaused) return; 
    try { 
        const res = await secureFetch('/api/events'); 
        if (res.status === 401) { 
            window.location.href = '/login'; 
            return; 
        } 
        if (res.ok) { 
            allEvents = await res.json(); 
            renderTable(); 
        } 
    } catch (e) { 
        console.error("Error fetching events:", e); 
    } 
}

void fetchEvents();
setInterval(() => { void fetchEvents(); }, 3000);
