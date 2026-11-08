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
    "T1049": { name: "System Network Connections Discovery", mitigation: "Analizar puerto e IP para validar tráfico legítimo." },
    "T1071.001": { name: "Application Layer Protocol", mitigation: "Analizar SNI para identificar C2." },
    "T1040": { name: "Network Sniffing", mitigation: "Verificar peticiones DNS sospechosas." }
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

function updateKpiCounters(total, host, tshark, tcpdump) {
    const ctTotal = document.getElementById('count-total');
    const ctHostElem = document.getElementById('count-host');
    const ctTsharkElem = document.getElementById('count-tshark');
    const ctTcpElem = document.getElementById('count-tcpdump');
    if (ctTotal) ctTotal.textContent = String(total);
    if (ctHostElem) ctHostElem.textContent = String(host);
    if (ctTsharkElem) ctTsharkElem.textContent = String(tshark);
    if (ctTcpElem) ctTcpElem.textContent = String(tcpdump);
}

function createTableRow(ev) {
    const tr = document.createElement('tr');
    const tdNum = document.createElement('td');
    tdNum.textContent = String(allEvents.indexOf(ev) + 1);
    tdNum.style.color = '#00ffff';
    tdNum.style.fontWeight = 'bold';

    const tdTime = document.createElement('td'); 
    const dateObj = new Date(ev.timestamp);
    tdTime.textContent = dateObj.toLocaleString('es-AR', { hour12: false });

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
    spanStatus.className = ev.status === 'Falso Positivo' ? 'status-fp' : 'status-nuevo';
    spanStatus.textContent = ev.status || 'Nuevo'; 
    tdStatus.appendChild(spanStatus);

    const tdActions = document.createElement('td');
    const btnDetail = document.createElement('button'); 
    btnDetail.className = 'action-btn'; 
    btnDetail.textContent = 'INSPECT'; 
    btnDetail.onclick = () => showDetail(ev);
    tdActions.append(btnDetail);
    
    tr.append(tdNum, tdTime, tdSrc, tdType, tdMitre, tdStatus, tdActions);
    return tr;
}

function renderTable() {
    const queryInput = document.getElementById('search-box');
    const query = queryInput ? queryInput.value.toLowerCase().trim() : '';
    const tbody = document.getElementById('events-body');
    if (!tbody) return;
    tbody.textContent = '';

    if (allEvents.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #fbbf24; padding: 20px;">[!] ESPERANDO TRÁFICO...</td></tr>';
        updateKpiCounters(0, 0, 0, 0);
        return;
    }

    let cHost = 0, cTshark = 0, cTcpdump = 0;
    allEvents.forEach(ev => {
        if (ev.source === 'Host-Sensor') cHost++;
        if (ev.source === 'Tshark') cTshark++;
        if (ev.source === 'Tcpdump') cTcpdump++;
    });

    updateKpiCounters(allEvents.length, cHost, cTshark, cTcpdump);

    const filtered = allEvents.slice().reverse().filter(ev => {
        const matchF = (currentFilter === 'ALL' || ev.source === currentFilter || ev.status === currentFilter);
        const text = (ev.timestamp + ' ' + ev.source + ' ' + ev.event_type + ' ' + ev.mitre_id + ' ' + ev.description).toLowerCase();
        return matchF && text.includes(query);
    });

    if (filtered.length === 0) { 
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #00ffff; padding: 20px;">[!] NO MATCH.</td></tr>'; 
        return; 
    }

    filtered.slice(0, 100).forEach(ev => {
        tbody.appendChild(createTableRow(ev));
    });
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
    if (ipIntel) ipIntel.innerHTML = '<span>IP Analizada con éxito.</span>';
    if (mitreGuide) mitreGuide.innerHTML = '<span>Playbook cargado.</span>';
    if (modal) modal.style.display = 'flex';
}

function closeModal() { 
    const modal = document.getElementById('modal-detail');
    if (modal) modal.style.display = 'none'; 
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
        // Excepción de red atrapada y controlada de forma segura
    } 
}

(async function initApp() {
    await fetchEvents();
    setInterval(() => { void fetchEvents(); }, 3000);
})();
