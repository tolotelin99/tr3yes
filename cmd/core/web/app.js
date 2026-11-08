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
