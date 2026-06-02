import sqlite3
import os
import pandas as pd
import numpy as np
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)
DB_FILE = "discovered_macs.db"

CAR_VENDORS = [
    'Tesla', 'BMW', 'Audi', 'Ford', 'Toyota', 'Volkswagen', 'Daimler', 'Mercedes', 'General Motors', 
    'Hyundai', 'Honda', 'Subaru', 'Volvo', 'Renault', 'Nissan', 'Mitsubishi', 'Mazda', 'Porsche', 
    'Kia', 'Lexus', 'Ferrari', 'Lamborghini', 'Bentley', 'Bugatti', 'Buick', 'Cadillac', 'Chevrolet', 
    'GMC', 'Infiniti', 'Jeep', 'Lincoln', 'Maserati', 'Mini', 'Ram', 'Rolls-Royce', 'Smart', 'Acura', 
    'Alfa Romeo', 'Aston Martin', 'Genesis', 'Lotus', 'McLaren', 'Rivian', 'Lucid', 'Fisker', 
    'Polestar', 'BYD', 'NIO', 'Xpeng', 'Geely', 'Chery', 'Changan', 'Great Wall', 'SAIC', 'FAW', 
    'Dongfeng', 'GAC', 'JAC', 'BAIC', 'Fibocom Auto', 'Harman', 'Visteon', 'Continental', 'Denso', 
    'Bosch', 'Valeo', 'Lear', 'Adient', 'Magna', 'Faurecia', 'Aptiv', 'BorgWarner', 'ZF', 'Autoliv', 
    'Panasonic Automotive', 'Pioneer', 'Kenwood', 'Alpine', 'Clarion'
]

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac TEXT,
            type TEXT,
            vendor TEXT,
            ssid TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS safe_devices (
            mac TEXT PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>WIFISNIFFER - Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1a1a1a; color: #e0e0e0; margin: 0; padding: 20px; }
        .container { max-width: 1400px; margin: auto; }
        h1 { color: #00ffcc; border-bottom: 2px solid #333; padding-bottom: 10px; margin-top: 0; }
        .nav { display: flex; gap: 10px; margin-bottom: 20px; border-bottom: 1px solid #333; padding-bottom: 10px; }
        .nav-item { padding: 10px 20px; background: #252525; border-radius: 4px; cursor: pointer; border: 1px solid transparent; }
        .nav-item:hover { background: #333; }
        .nav-item.active { border-color: #00ffcc; color: #00ffcc; background: #2d2d2d; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        table { width: 100%; border-collapse: collapse; background: #252525; border-radius: 8px; overflow: hidden; margin-top: 10px; }
        th { background: #333; color: #00ffcc; text-align: left; padding: 12px; cursor: pointer; user-select: none; position: relative; }
        th:hover { background: #444; }
        th::after { content: '↕'; position: absolute; right: 8px; color: #666; font-size: 12px; }
        th.sort-asc::after { content: '↑'; color: #00ffcc; }
        th.sort-desc::after { content: '↓'; color: #00ffcc; }
        td { padding: 12px; border-bottom: 1px solid #333; }
        tr:hover { background: #2d2d2d; }
        .history-layout { display: grid; grid-template-columns: 350px 1fr; gap: 20px; }
        .device-list { background: #252525; border-radius: 8px; height: 70vh; overflow-y: auto; padding: 10px; }
        .device-item { padding: 10px; border-bottom: 1px solid #333; cursor: pointer; border-radius: 4px; margin-bottom: 5px; position: relative; }
        .device-item:hover { background: #333; }
        .device-item.selected { background: #004444; border-left: 4px solid #00ffcc; }
        .timeline { background: #252525; border-radius: 8px; padding: 20px; height: 70vh; overflow-y: auto; }
        .btn { padding: 5px 10px; border-radius: 4px; cursor: pointer; border: none; font-size: 12px; font-weight: bold; }
        .btn-safe { background: #00cc66; color: white; }
        .btn-unsafe { background: #ff3333; color: white; }
        .score-high { color: #ff3333; font-weight: bold; }
        .score-mid { color: #ff9900; }
        .score-low { color: #00ffcc; }
        .type-ap { color: #ff9900; font-weight: bold; }
        .type-dev { color: #00ccff; }
        .badge { padding: 2px 6px; border-radius: 4px; font-size: 12px; background: #444; }
        code { background: #111; padding: 2px 4px; border-radius: 3px; color: #ff66cc; }
    </style>
</head>
<body>
    <div class="container">
        <h1>WIFISNIFFER</h1>
        <div class="nav">
            <div class="nav-item active" onclick="showTab('live', this)">Live</div>
            <div class="nav-item" onclick="showTab('history', this)">History</div>
            <div class="nav-item" onclick="showTab('cars', this)">Cars</div>
            <div class="nav-item" onclick="showTab('regressions', this)">Regressions</div>
            <div class="nav-item" onclick="showTab('analysis', this)">Analysis</div>
            <div class="nav-item" onclick="showTab('safe', this)">Safe Records</div>
        </div>

        <div id="live" class="tab-content active">
            <div style="margin-bottom: 15px; background: #252525; padding: 10px; border-radius: 8px; display: inline-block;">
                <label style="cursor: pointer; user-select: none;">
                    <input type="checkbox" id="hide-safe" onchange="renderLiveTable(cachedLiveData)"> Hide Safe Devices
                </label>
            </div>
            <table>
                <thead>
                    <tr>
                        <th onclick="setSort('mac')">MAC</th>
                        <th onclick="setSort('type')">Type</th>
                        <th onclick="setSort('vendor')">Vendor</th>
                        <th onclick="setSort('hits')">Hits</th>
                        <th onclick="setSort('last_seen')">Last Seen</th>
                        <th onclick="setSort('ssids')">SSID</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="live-table"></tbody>
            </table>
        </div>

        <div id="history" class="tab-content">
            <div class="history-layout">
                <div class="device-list" id="device-list"></div>
                <div id="timeline" class="timeline">
                    <h3 style="text-align: center; margin-top: 100px; color: #666;">Select a device</h3>
                </div>
            </div>
        </div>

        <div id="cars" class="tab-content">
            <h2>Car Detections</h2>
            <table>
                <thead>
                    <tr>
                        <th>MAC</th>
                        <th>Vendor</th>
                        <th>Hits</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                        <th>SSID(s)</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="cars-table"></tbody>
            </table>
        </div>

        <div id="regressions" class="tab-content">
            <h2>Returning Devices (Regressions)</h2>
            <p style="color: #888;">Devices seen across multiple days or after significant gaps.</p>
            <table>
                <thead>
                    <tr>
                        <th>MAC</th>
                        <th>Vendor</th>
                        <th>Days Active</th>
                        <th>Total Hits</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="regressions-table"></tbody>
            </table>
        </div>

        <div id="analysis" class="tab-content">
            <h2>Anomaly Analysis</h2>
            <table>
                <thead><tr><th>MAC</th><th>Score</th><th>Vendor</th><th>Detected Anomalies</th><th>SSID(s)</th><th>Actions</th></tr></thead>
                <tbody id="analysis-table"></tbody>
            </table>
        </div>

        <div id="safe" class="tab-content">
            <h2>Safe Devices</h2>
            <table>
                <thead>
                    <tr>
                        <th>MAC</th>
                        <th>Type</th>
                        <th>Vendor</th>
                        <th>Hits</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                        <th>Known SSIDs</th>
                        <th>Marked Safe On</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody id="safe-table"></tbody>
            </table>
        </div>
    </div>

    <script>
        let currentTab = 'live';
        let selectedMac = null;
        let liveSort = { column: 'last_seen', direction: 'desc' };
        let cachedLiveData = [];
        let cachedSafeMacs = [];

        function showTab(tabId, el) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            el.classList.add('active');
            currentTab = tabId;
            if (tabId === 'history') loadHistoryList();
            if (tabId === 'cars') loadCarsList();
            if (tabId === 'regressions') loadRegressionsList();
            if (tabId === 'analysis') loadAnalysis();
            if (tabId === 'safe') loadSafeList();
        }

        async function loadRegressionsList() {
            const res = await fetch('/api/regressions');
            const data = await res.json();
            const table = document.getElementById('regressions-table');
            let html = '';
            data.forEach(dev => {
                html += `
                    <tr>
                        <td><code>${dev.mac}</code></td>
                        <td>${dev.vendor}</td>
                        <td><span class="badge">${dev.days_seen} days</span></td>
                        <td>${dev.hits}</td>
                        <td>${dev.first_seen}</td>
                        <td>${dev.last_seen}</td>
                        <td>
                            <button class="btn btn-safe" onclick="showHistory('${dev.mac}')">View Logs</button>
                        </td>
                    </tr>`;
            });
            table.innerHTML = html;
        }

        async function loadCarsList() {
            const res = await fetch('/api/cars');
            const data = await res.json();
            const table = document.getElementById('cars-table');
            let html = '';
            data.forEach(dev => {
                html += `
                    <tr>
                        <td><code>${dev.mac}</code></td>
                        <td>${dev.vendor}</td>
                        <td><span class="badge">${dev.hits}</span></td>
                        <td>${dev.first_seen}</td>
                        <td>${dev.last_seen}</td>
                        <td>${dev.ssids || ''}</td>
                        <td>
                            <button class="btn btn-safe" onclick="showHistory('${dev.mac}')">View Logs</button>
                        </td>
                    </tr>`;
            });
            table.innerHTML = html;
        }

        function showHistory(mac) {
            selectedMac = mac;
            const navItems = document.querySelectorAll('.nav-item');
            let historyNavItem;
            navItems.forEach(n => {
                if (n.innerText === 'History') historyNavItem = n;
            });
            showTab('history', historyNavItem);
            loadTimeline(mac);
        }

        function setSort(column) {
            if (liveSort.column === column) {
                liveSort.direction = liveSort.direction === 'asc' ? 'desc' : 'asc';
            } else {
                liveSort.column = column;
                liveSort.direction = 'desc';
            }
            document.querySelectorAll('#live th').forEach(th => {
                th.classList.remove('sort-asc', 'sort-desc');
                if (th.getAttribute('onclick') && th.getAttribute('onclick').includes(`'${column}'`)) {
                    th.classList.add(liveSort.direction === 'asc' ? 'sort-asc' : 'sort-desc');
                }
            });
            renderLiveTable(cachedLiveData);
        }

        async function markSafe(mac) {
            await fetch('/api/mark_safe', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({mac}) });
            await updateSafeCache();
            if (currentTab === 'live') updateLive();
            if (currentTab === 'analysis') loadAnalysis();
            if (currentTab === 'history' && selectedMac === mac) loadTimeline(mac);
        }

        async function unmarkSafe(mac) {
            await fetch('/api/unmark_safe', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({mac}) });
            await updateSafeCache();
            if (currentTab === 'safe') loadSafeList();
            if (currentTab === 'live') updateLive();
        }

        async function updateSafeCache() {
            const resSafe = await fetch('/api/safe_list');
            const safeList = await resSafe.json();
            cachedSafeMacs = safeList.map(s => s.mac);
        }

        async function renderLiveTable(data) {
            const table = document.getElementById('live-table');
            const hideSafe = document.getElementById('hide-safe').checked;
            
            let html = '';
            const sortedData = [...data].sort((a, b) => {
                let valA = a[liveSort.column] || '';
                let valB = b[liveSort.column] || '';
                if (liveSort.column === 'hits') { valA = parseInt(valA); valB = parseInt(valB); }
                if (valA < valB) return liveSort.direction === 'asc' ? -1 : 1;
                if (valA > valB) return liveSort.direction === 'asc' ? 1 : -1;
                return 0;
            });

            sortedData.forEach(dev => {
                const isSafe = cachedSafeMacs.includes(dev.mac);
                if (hideSafe && isSafe) return;
                const btn = isSafe ? '<span style="color:#0c6;">Safe</span>' : `<button class="btn btn-safe" onclick="markSafe('${dev.mac}')">Mark Safe</button>`;
                html += `<tr><td><code>${dev.mac}</code></td><td class="${dev.type === 'Access Point' ? 'type-ap' : 'type-dev'}">${dev.type}</td><td>${dev.vendor}</td><td><span class="badge">${dev.hits}</span></td><td>${dev.last_seen}</td><td>${dev.ssids || ''}</td><td>${btn}</td></tr>`;
            });
            table.innerHTML = html;
        }

        async function updateLive() {
            if (currentTab !== 'live') return;
            const resData = await fetch('/api/data');
            const data = await resData.json();
            cachedLiveData = data;
            renderLiveTable(data);
        }

        async function loadHistoryList() {
            const res = await fetch('/api/data');
            const data = await res.json();
            const list = document.getElementById('device-list');
            list.innerHTML = '<h3>All Devices</h3>';
            const fragment = document.createDocumentFragment();
            data.forEach(dev => {
                const div = document.createElement('div');
                div.className = `device-item ${selectedMac === dev.mac ? 'selected' : ''}`;
                div.onclick = () => loadTimeline(dev.mac);
                div.innerHTML = `<strong>${dev.mac}</strong><br><small>${dev.vendor}</small><br><small style="color: #888;">${dev.ssids || ''}</small>`;
                fragment.appendChild(div);
            });
            list.appendChild(fragment);
        }

        async function loadTimeline(mac) {
            selectedMac = mac;
            loadHistoryList();
            const [resHist, resSafe] = await Promise.all([fetch(`/api/history?mac=${mac}`), fetch(`/api/is_safe?mac=${mac}`)]);
            const logs = await resHist.json();
            const isSafe = (await resSafe.json()).safe;
            
            const timeline = document.getElementById('timeline');
            let html = `<div style="display:flex; justify-content:space-between; align-items:center;"><h3>History: ${mac}</h3>${isSafe ? '<span style="color:#0c6;">[SAFE]</span>' : `<button class="btn btn-safe" onclick="markSafe('${mac}')">Mark Safe</button>`}</div>`;
            html += '<table><thead><tr><th>Time</th><th>Type</th><th>SSID</th></tr></thead><tbody>';
            logs.forEach(l => { html += `<tr><td>${l.timestamp}</td><td>${l.type}</td><td>${l.ssid || ''}</td></tr>`; });
            html += '</tbody></table>';
            timeline.innerHTML = html;
        }

        async function loadAnalysis() {
            const res = await fetch('/api/analysis');
            const data = await res.json();
            const table = document.getElementById('analysis-table');
            let html = '';
            data.forEach(r => {
                const scoreClass = r.score > 60 ? 'score-high' : (r.score > 30 ? 'score-mid' : 'score-low');
                html += `<tr><td><code>${r.mac}</code></td><td class="${scoreClass}">${r.score}</td><td>${r.vendor}</td><td>${r.reasons}</td><td>${r.ssids || ''}</td><td><button class="btn btn-safe" onclick="markSafe('${r.mac}')">Mark Safe</button></td></tr>`;
            });
            table.innerHTML = html;
        }

        async function loadSafeList() {
            const res = await fetch('/api/safe_list');
            const data = await res.json();
            const table = document.getElementById('safe-table');
            let html = '';
            data.forEach(dev => {
                html += `
                    <tr>
                        <td><code>${dev.mac}</code></td>
                        <td class="${dev.type === 'Access Point' ? 'type-ap' : 'type-dev'}">${dev.type}</td>
                        <td>${dev.vendor}</td>
                        <td><span class="badge">${dev.hits}</span></td>
                        <td>${dev.first_seen}</td>
                        <td>${dev.last_seen}</td>
                        <td>${dev.ssids || ''}</td>
                        <td>${dev.marked_at}</td>
                        <td><button class="btn btn-unsafe" onclick="unmarkSafe('${dev.mac}')">Unmark</button></td>
                    </tr>`;
            });
            table.innerHTML = html;
        }

        // Initial load
        updateSafeCache().then(() => {
            updateLive();
            setInterval(updateLive, 2000);
            // Refresh safe cache less frequently
            setInterval(updateSafeCache, 10000);
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index(): return render_template_string(HTML_TEMPLATE)

@app.route('/api/data')
def get_data():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT mac, type, vendor, hits, last_seen, ssids FROM device_summary ORDER BY last_seen DESC')
    cols = [c[0] for c in cursor.description]
    data = [dict(zip(cols, r)) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)

@app.route('/api/history')
def get_history():
    mac = request.args.get('mac')
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # Use the index on mac
    cursor.execute('SELECT type, ssid, timestamp FROM detections WHERE mac = ? ORDER BY timestamp DESC LIMIT 1000', (mac,))
    cols = [c[0] for c in cursor.description]
    data = [dict(zip(cols, r)) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)

@app.route('/api/mark_safe', methods=['POST'])
def mark_safe():
    mac = request.json.get('mac')
    conn = sqlite3.connect(DB_FILE)
    conn.execute('INSERT OR IGNORE INTO safe_devices (mac) VALUES (?)', (mac,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/api/unmark_safe', methods=['POST'])
def unmark_safe():
    mac = request.json.get('mac')
    conn = sqlite3.connect(DB_FILE)
    conn.execute('DELETE FROM safe_devices WHERE mac = ?', (mac,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/api/safe_list')
def safe_list():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT 
            s.mac, 
            s.timestamp as marked_at,
            ds.type,
            ds.vendor,
            ds.hits,
            ds.first_seen,
            ds.last_seen,
            ds.ssids 
        FROM safe_devices s 
        LEFT JOIN device_summary ds ON s.mac = ds.mac 
        ORDER BY s.timestamp DESC
    ''')
    cols = [c[0] for c in cursor.description]
    data = [dict(zip(cols, r)) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)

@app.route('/api/is_safe')
def is_safe():
    mac = request.args.get('mac')
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM safe_devices WHERE mac = ?', (mac,))
    res = cursor.fetchone()
    conn.close()
    return jsonify({"safe": bool(res)})

@app.route('/api/analysis')
def get_analysis():
    conn = sqlite3.connect(DB_FILE)
    # Only analyze devices seen in the last 24 hours to reduce memory load, 
    # but include their full history for those specific MACs.
    # First, get candidate MACs
    cursor = conn.cursor()
    cursor.execute('''
        SELECT mac FROM device_summary 
        WHERE last_seen > datetime('now', '-24 hours')
        AND mac NOT IN (SELECT mac FROM safe_devices)
    ''')
    candidate_macs = [r[0] for r in cursor.fetchall()]
    
    if not candidate_macs:
        conn.close()
        return jsonify([])

    # Fetch history only for these MACs
    placeholders = ','.join(['?'] * len(candidate_macs))
    df = pd.read_sql_query(f'SELECT * FROM detections WHERE mac IN ({placeholders})', conn, params=candidate_macs)
    conn.close()
    
    if df.empty: return jsonify([])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    results = []
    for mac in df['mac'].unique():
        m_data = df[df['mac'] == mac].sort_values('timestamp')
        reasons, score = [], 0
        m_data['diff'] = m_data['timestamp'].diff().dt.total_seconds() / 60
        num_visits = (m_data['diff'] > 15).sum() + 1
        if num_visits >= 2:
            reasons.append(f"Mobile Pattern ({num_visits} visits)")
            score += 25 * min(num_visits, 4)
        hr_range = np.ptp(m_data['hour'].unique()) if len(m_data['hour'].unique()) > 0 else 0
        if len(m_data) > 20 and hr_range <= 2:
            reasons.append(f"Time Clustered ({hr_range+1}h window)")
            score += 20
        night_ratio = (m_data['hour'].isin([23,0,1,2,3,4,5])).mean()
        if night_ratio > 0.7:
            reasons.append("Night Owl")
            score += 30
        ssids = ",".join(m_data['ssid'].dropna().unique())
        if score > 0:
            results.append({"mac": mac, "score": int(score), "vendor": m_data['vendor'].iloc[0], "reasons": ", ".join(reasons), "ssids": ssids})
    return jsonify(sorted(results, key=lambda x: x['score'], reverse=True))

@app.route('/api/cars')
def get_cars():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    like_clauses = " OR ".join(["vendor LIKE ?" for _ in CAR_VENDORS])
    params = [f"%{v}%" for v in CAR_VENDORS]
    
    query = f'''
        SELECT 
            mac, 
            vendor, 
            hits, 
            first_seen, 
            last_seen, 
            ssids 
        FROM device_summary 
        WHERE {like_clauses} 
        ORDER BY last_seen DESC
    '''
    cursor.execute(query, params)
    cols = [c[0] for c in cursor.description]
    data = [dict(zip(cols, r)) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)

@app.route('/api/regressions')
def get_regressions():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    # For regressions, we still need some detail from detections if we want 'days_seen',
    # but we can optimize it by first filtering device_summary.
    cursor.execute('''
        SELECT 
            ds.mac, 
            ds.vendor, 
            COUNT(DISTINCT date(d.timestamp)) as days_seen,
            ds.hits,
            ds.first_seen,
            ds.last_seen
        FROM device_summary ds
        JOIN detections d ON ds.mac = d.mac
        WHERE ds.hits > 1
        GROUP BY ds.mac 
        HAVING days_seen > 1 OR (ds.last_seen != ds.first_seen AND ds.first_seen < datetime('now', '-1 day'))
        ORDER BY ds.last_seen DESC
    ''', ())
    cols = [c[0] for c in cursor.description]
    data = [dict(zip(cols, r)) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)

if __name__ == "__main__":
    init_db()
    app.run(host='0.0.0.0', port=5000)
