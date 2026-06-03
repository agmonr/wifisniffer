import sqlite3
import os
import io
import csv
import pandas as pd
import numpy as np
from flask import Flask, jsonify, render_template_string, request, Response

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
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.execute('PRAGMA journal_mode=WAL')
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
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_detections_mac ON detections(mac)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp)')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS device_summary (
            mac TEXT PRIMARY KEY,
            type TEXT,
            vendor TEXT,
            hits INTEGER DEFAULT 0,
            first_seen TIMESTAMP,
            last_seen TIMESTAMP,
            ssids TEXT
        )
    ''')
    
    cursor.execute('''
    CREATE TRIGGER IF NOT EXISTS update_device_summary AFTER INSERT ON detections
    BEGIN
        INSERT INTO device_summary (mac, type, vendor, hits, first_seen, last_seen, ssids)
        VALUES (NEW.mac, NEW.type, NEW.vendor, 1, NEW.timestamp, NEW.timestamp, NEW.ssid)
        ON CONFLICT(mac) DO UPDATE SET
            hits = hits + 1,
            last_seen = NEW.timestamp,
            ssids = CASE 
                WHEN ssids IS NULL OR ssids = '' THEN NEW.ssid
                WHEN NEW.ssid IS NULL OR NEW.ssid = '' THEN ssids
                WHEN INSTR(',' || ssids || ',', ',' || NEW.ssid || ',') = 0 THEN ssids || ',' || NEW.ssid
                ELSE ssids
            END,
            type = CASE WHEN NEW.type = 'Access Point' THEN 'Access Point' ELSE type END;
    END;
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
        .search-container { margin-bottom: 15px; display: flex; gap: 10px; align-items: center; }
        .search-input { padding: 8px 12px; border-radius: 4px; border: 1px solid #333; background: #252525; color: #fff; width: 300px; }
        .pagination { display: flex; gap: 5px; margin-top: 15px; justify-content: center; }
        .page-btn { padding: 5px 10px; background: #333; border: 1px solid #444; color: #fff; cursor: pointer; border-radius: 4px; }
        .page-btn.active { background: #00ffcc; color: #1a1a1a; font-weight: bold; }
        .page-btn:disabled { opacity: 0.5; cursor: not-allowed; }
        .copy-btn { background: transparent; border: none; color: #666; cursor: pointer; padding: 2px 5px; font-size: 14px; border-radius: 4px; transition: color 0.2s; }
        .copy-btn:hover { color: #00ffcc; background: #333; }
        #toast { 
            position: fixed; bottom: 20px; right: 20px; background: #00ffcc; color: #1a1a1a; 
            padding: 10px 20px; border-radius: 4px; font-weight: bold; 
            opacity: 0; transition: opacity 0.3s; pointer-events: none; z-index: 1000;
        }
    </style>
</head>
<body>
    <div id="toast">Copied to clipboard!</div>
    <div class="container">
        <h1>WIFISNIFFER</h1>
        <div class="nav">
            <div class="nav-item active" onclick="showTab('live', this)">Live</div>
            <div class="nav-item" onclick="showTab('history', this)">History</div>
            <div class="nav-item" onclick="showTab('cars', this)">Cars</div>
            <div class="nav-item" onclick="showTab('regressions', this)">Regressions</div>
            <div class="nav-item" onclick="showTab('analysis', this)">Analysis</div>
            <div class="nav-item" onclick="showTab('safe', this)">Safe Records</div>
            <div class="nav-item" onclick="showTab('maintenance', this)">Maintenance</div>
        </div>

        <div class="search-container">
            <input type="text" id="global-search" class="search-input" placeholder="Search MAC, Vendor, or SSID..." oninput="handleSearch()">
            <label style="cursor: pointer; user-select: none; margin-left: 10px; font-size: 14px;">
                <input type="checkbox" id="hide-safe" onchange="handleSearch()"> Hide Safe
            </label>
            <label style="cursor: pointer; user-select: none; margin-left: 10px; font-size: 14px;">
                <input type="checkbox" id="hide-unknown" onchange="handleSearch()"> Hide Unknown/Random
            </label>
            <button class="btn btn-safe" style="margin-left: 10px;" onclick="exportCurrentView()">Export to CSV</button>
            <div id="pagination-controls" class="pagination"></div>
        </div>

        <div id="live" class="tab-content active">
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

        <div id="maintenance" class="tab-content">
            <h2>Database Maintenance</h2>
            <div style="background: #252525; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
                <h3>Statistics</h3>
                <div id="db-stats" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px;">
                    <div style="background: #333; padding: 15px; border-radius: 4px;">
                        <div style="color: #888; font-size: 12px; margin-bottom: 5px;">DATABASE SIZE</div>
                        <div id="stat-size" style="font-size: 24px; color: #00ffcc;">-</div>
                    </div>
                    <div style="background: #333; padding: 15px; border-radius: 4px;">
                        <div style="color: #888; font-size: 12px; margin-bottom: 5px;">TOTAL DETECTIONS</div>
                        <div id="stat-detections" style="font-size: 24px; color: #00ffcc;">-</div>
                    </div>
                    <div style="background: #333; padding: 15px; border-radius: 4px;">
                        <div style="color: #888; font-size: 12px; margin-bottom: 5px;">UNIQUE DEVICES</div>
                        <div id="stat-devices" style="font-size: 24px; color: #00ffcc;">-</div>
                    </div>
                </div>
            </div>

            <div style="background: #252525; padding: 20px; border-radius: 8px;">
                <h3>Cleanup Tasks</h3>
                <p style="color: #888;">Remove old records to keep the database performant.</p>
                <div style="display: flex; gap: 10px; align-items: center;">
                    <button class="btn btn-unsafe" style="padding: 10px 20px;" onclick="cleanOldRecords()">Purge Records Older Than 30 Days</button>
                    <span id="clean-status" style="font-size: 14px; color: #888;"></span>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Global error handler
        window.onerror = function(msg, url, line) {
            console.error(`JS Error: ${msg} at ${url}:${line}`);
            showToast(`JS Error: ${msg}`);
            return false;
        };

        let currentTab = 'live';
        let selectedMac = null;
        let liveSort = { column: 'last_seen', direction: 'desc' };
        let cachedLiveData = [];
        let cachedSafeMacs = [];
        let currentPage = 1;
        const itemsPerPage = 50;
        let currentRawData = []; // Stores the raw data for the current tab

        function showTab(tabId, el) {
            document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
            document.getElementById(tabId).classList.add('active');
            el.classList.add('active');
            currentTab = tabId;
            currentPage = 1;
            document.getElementById('global-search').value = '';
            refreshTab();
        }

        function exportCurrentView() {
            const filtered = getFilteredData(currentRawData);
            if (filtered.length === 0) { showToast('No data to export'); return; }

            const headers = Object.keys(filtered[0]);
            const csvRows = [headers.join(',')];
            
            for (const row of filtered) {
                const values = headers.map(header => {
                    const val = row[header] === null ? '' : row[header];
                    const escaped = ('' + val).replace(/"/g, '""');
                    return `"${escaped}"`;
                });
                csvRows.push(values.join(','));
            }
            
            const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.setAttribute('hidden', '');
            a.setAttribute('href', url);
            a.setAttribute('download', `wifisniffer_${currentTab}_${new Date().toISOString().split('T')[0]}.csv`);
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }

        function copyToClipboard(text) {
            if (!navigator.clipboard) {
                // Fallback for non-secure contexts (like some SSH tunnel setups)
                const textArea = document.createElement("textarea");
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                try {
                    document.execCommand('copy');
                    showToast(`Copied: ${text}`);
                } catch (err) {
                    console.error('Fallback copy failed', err);
                }
                document.body.removeChild(textArea);
                return;
            }
            navigator.clipboard.writeText(text).then(() => {
                showToast(`Copied: ${text}`);
            }).catch(err => {
                console.error('Clipboard write failed', err);
            });
        }

        function showToast(message) {
            const toast = document.getElementById('toast');
            toast.innerText = message;
            toast.style.opacity = '1';
            setTimeout(() => { toast.style.opacity = '0'; }, 2000);
        }

        function refreshTab() {
            if (currentTab === 'live') renderLiveTable(cachedLiveData);
            if (currentTab === 'history') loadHistoryList();
            if (currentTab === 'cars') loadCarsList();
            if (currentTab === 'regressions') loadRegressionsList();
            if (currentTab === 'analysis') loadAnalysis();
            if (currentTab === 'safe') loadSafeList();
            if (currentTab === 'maintenance') loadMaintenanceStats();
        }

        async function loadMaintenanceStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                document.getElementById('stat-size').innerText = data.size;
                document.getElementById('stat-detections').innerText = data.detections.toLocaleString();
                document.getElementById('stat-devices').innerText = data.devices.toLocaleString();
            } catch (e) {
                console.error("Failed to load maintenance stats:", e);
            }
        }

        async function cleanOldRecords() {
            if (!confirm('Are you sure you want to delete all records older than 30 days? This action cannot be undone.')) return;
            
            const status = document.getElementById('clean-status');
            status.innerText = 'Cleaning...';
            status.style.color = '#888';
            
            try {
                const res = await fetch('/api/maintenance/clean', { method: 'POST' });
                const data = await res.json();
                status.innerText = `Success: ${data.deleted} records removed.`;
                status.style.color = '#00cc66';
                loadMaintenanceStats();
            } catch (err) {
                status.innerText = 'Error performing cleanup.';
                status.style.color = '#ff3333';
            }
        }

        function handleSearch() {
            currentPage = 1;
            refreshTab();
        }

        function getFilteredData(data) {
            const query = document.getElementById('global-search').value.toLowerCase();
            const hideSafe = document.getElementById('hide-safe').checked;
            const hideUnknown = document.getElementById('hide-unknown').checked;
            
            let filtered = data;
            if (query) {
                filtered = filtered.filter(d => 
                    (d.mac && d.mac.toLowerCase().includes(query)) || 
                    (d.vendor && d.vendor.toLowerCase().includes(query)) || 
                    (d.ssids && d.ssids.toLowerCase().includes(query))
                );
            }

            if (hideSafe && currentTab !== 'safe') {
                filtered = filtered.filter(d => !cachedSafeMacs.includes(d.mac));
            }

            if (hideUnknown) {
                filtered = filtered.filter(d => {
                    const isUnknown = d.vendor === 'Unknown';
                    // Randomized MACs have 2, 6, A, or E as the second hex digit
                    const isRandom = d.mac && /^[0-9a-f][26ae]/i.test(d.mac);
                    return !isUnknown && !isRandom;
                });
            }
            return filtered;
        }

        function renderPagination(totalItems) {
            const container = document.getElementById('pagination-controls');
            const totalPages = Math.ceil(totalItems / itemsPerPage);
            if (totalPages <= 1) { container.innerHTML = ''; return; }
            
            let html = `<button class="page-btn" ${currentPage === 1 ? 'disabled' : ''} onclick="changePage(${currentPage - 1})">Prev</button>`;
            
            const start = Math.max(1, currentPage - 2);
            const end = Math.min(totalPages, currentPage + 2);
            
            if (start > 1) html += '<button class="page-btn" onclick="changePage(1)">1</button><span>...</span>';
            
            for (let i = start; i <= end; i++) {
                html += `<button class="page-btn ${i === currentPage ? 'active' : ''}" onclick="changePage(${i})">${i}</button>`;
            }
            
            if (end < totalPages) html += `<span>...</span><button class="page-btn" onclick="changePage(${totalPages})">${totalPages}</button>`;
            
            html += `<button class="page-btn" ${currentPage === totalPages ? 'disabled' : ''} onclick="changePage(${currentPage + 1})">Next</button>`;
            container.innerHTML = html;
        }

        function changePage(page) {
            currentPage = page;
            refreshTab();
        }

        async function loadRegressionsList() {
            try {
                const res = await fetch('/api/regressions');
                const data = await res.json();
                currentRawData = data;
                const filtered = getFilteredData(data);
                renderPagination(filtered.length);
                const paged = filtered.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);
                
                const table = document.getElementById('regressions-table');
                let html = '';
                if (paged.length === 0) {
                    const msg = data.length === 0 ? 'Please wait, collecting data...' : 'No regressions found with current filters.';
                    html = `<tr><td colspan="7" style="text-align:center; padding:50px; color:#888;">${msg}</td></tr>`;
                } else {
                    paged.forEach(dev => {
                        html += `<tr><td><code>${dev.mac}</code> <button class="copy-btn" onclick="copyToClipboard('${dev.mac}')" title="Copy MAC">📋</button></td><td>${dev.vendor}</td><td><span class="badge">${dev.days_seen} days</span></td><td>${dev.hits}</td><td>${dev.first_seen}</td><td>${dev.last_seen}</td><td><div style="display:flex; gap:5px;"><button class="btn btn-safe" onclick="showHistory('${dev.mac}')">View Logs</button><button class="btn btn-safe" style="background:#555;" onclick="copyToClipboard('${dev.mac}, ${dev.vendor}')" title="Copy Row">Row</button></div></td></tr>`;
                    });
                }
                table.innerHTML = html;
            } catch (e) {
                console.error("Failed to load regressions:", e);
            }
        }

        async function loadCarsList() {
            try {
                const res = await fetch('/api/cars');
                const data = await res.json();
                currentRawData = data;
                const filtered = getFilteredData(data);
                renderPagination(filtered.length);
                const paged = filtered.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

                const table = document.getElementById('cars-table');
                let html = '';
                if (paged.length === 0) {
                    const msg = data.length === 0 ? 'Please wait, collecting data...' : 'No cars found with current filters.';
                    html = `<tr><td colspan="7" style="text-align:center; padding:50px; color:#888;">${msg}</td></tr>`;
                } else {
                    paged.forEach(dev => {
                        html += `<tr><td><code>${dev.mac}</code> <button class="copy-btn" onclick="copyToClipboard('${dev.mac}')" title="Copy MAC">📋</button></td><td>${dev.vendor}</td><td><span class="badge">${dev.hits}</span></td><td>${dev.first_seen}</td><td>${dev.last_seen}</td><td>${(dev.ssids || '').split(',').map(s => s ? `<a href="/api/export/ssid?ssid=${encodeURIComponent(s)}" title="Export History to CSV" style="color:#00ffcc; text-decoration:none; border-bottom:1px dotted #00ffcc;">${s}</a>` : '').join(', ')}</td><td><div style="display:flex; gap:5px;"><button class="btn btn-safe" onclick="showHistory('${dev.mac}')">View Logs</button><button class="btn btn-safe" style="background:#555;" onclick="copyToClipboard('${dev.mac}, ${dev.vendor}')" title="Copy Row">Row</button></div></td></tr>`;
                    });
                }
                table.innerHTML = html;
            } catch (e) {
                console.error("Failed to load cars:", e);
            }
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
            let filtered = getFilteredData(data);

            const sortedData = [...filtered].sort((a, b) => {
                let valA = a[liveSort.column] || '';
                let valB = b[liveSort.column] || '';
                if (liveSort.column === 'hits') { valA = parseInt(valA); valB = parseInt(valB); }
                if (valA < valB) return liveSort.direction === 'asc' ? -1 : 1;
                if (valA > valB) return liveSort.direction === 'asc' ? 1 : -1;
                return 0;
            });

            renderPagination(sortedData.length);
            const paged = sortedData.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

            let html = '';
            if (paged.length === 0) {
                const msg = data.length === 0 ? 'Please wait, collecting data...' : 'No results found with current filters.';
                html = `<tr><td colspan="7" style="text-align:center; padding:50px; color:#888;">${msg}</td></tr>`;
            } else {
                paged.forEach(dev => {
                    const isSafe = cachedSafeMacs.includes(dev.mac);
                    const btn = isSafe ? '<span style="color:#0c6;">Safe</span>' : `<button class="btn btn-safe" onclick="markSafe('${dev.mac}')">Mark Safe</button>`;
                    html += `<tr><td><code>${dev.mac}</code> <button class="copy-btn" onclick="copyToClipboard('${dev.mac}')" title="Copy MAC">📋</button></td><td class="${dev.type === 'Access Point' ? 'type-ap' : 'type-dev'}">${dev.type}</td><td>${dev.vendor}</td><td><span class="badge">${dev.hits}</span></td><td>${dev.last_seen}</td><td>${(dev.ssids || '').split(',').map(s => s ? `<a href="/api/export/ssid?ssid=${encodeURIComponent(s)}" title="Export History to CSV" style="color:#00ffcc; text-decoration:none; border-bottom:1px dotted #00ffcc;">${s}</a>` : '').join(', ')}</td><td><div style="display:flex; gap:5px;">${btn}<button class="btn btn-safe" style="background:#555;" onclick="copyToClipboard('${dev.mac}, ${dev.vendor}, ${dev.ssids || ''}')" title="Copy Row">Row</button></div></td></tr>`;
                });
            }
            table.innerHTML = html;
        }

        async function updateLive() {
            if (currentTab !== 'live') return;
            const resData = await fetch('/api/data');
            const data = await resData.json();
            cachedLiveData = data;
            currentRawData = data;
            renderLiveTable(data);
        }

        async function loadHistoryList() {
            try {
                const res = await fetch('/api/data');
                const data = await res.json();
                currentRawData = data;
                const filtered = getFilteredData(data);
                const displayData = filtered.slice(0, 500); 

                const list = document.getElementById('device-list');
                list.innerHTML = `<h3>Devices (${filtered.length})</h3>`;
                if (filtered.length === 0) {
                    const msg = data.length === 0 ? 'Please wait, collecting data...' : 'No devices match filters.';
                    list.innerHTML += `<div style="text-align:center; padding:20px; color:#888;">${msg}</div>`;
                    return;
                }
                const fragment = document.createDocumentFragment();
                displayData.forEach(dev => {
                    const div = document.createElement('div');
                    div.className = `device-item ${selectedMac === dev.mac ? 'selected' : ''}`;
                    div.onclick = () => loadTimeline(dev.mac);
                    div.innerHTML = `<strong>${dev.mac}</strong><br><small>${dev.vendor}</small><br><small style="color: #888;">${dev.ssids || ''}</small>`;
                    fragment.appendChild(div);
                });
                list.appendChild(fragment);
                if (filtered.length > 500) {
                    const more = document.createElement('div');
                    more.style = 'text-align:center; padding:10px; color:#888;';
                    more.innerText = 'Use search to find more...';
                    list.appendChild(more);
                }
            } catch (e) {
                console.error("Failed to load device list:", e);
            }
        }

        async function loadTimeline(mac) {
            try {
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
            } catch (e) {
                console.error("Failed to load timeline:", e);
                document.getElementById('timeline').innerHTML = `<h3 style="color:#ff3333;">Error loading history for ${mac}</h3>`;
            }
        }

        async function loadAnalysis() {
            try {
                const res = await fetch('/api/analysis');
                const data = await res.json();
                currentRawData = data;
                const filtered = getFilteredData(data);
                renderPagination(filtered.length);
                const paged = filtered.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

                const table = document.getElementById('analysis-table');
                let html = '';
                if (paged.length === 0) {
                    const msg = data.length === 0 ? 'Please wait, collecting data...' : 'No anomalies found with current filters.';
                    html = `<tr><td colspan="6" style="text-align:center; padding:50px; color:#888;">${msg}</td></tr>`;
                } else {
                    paged.forEach(r => {
                        const scoreClass = r.score > 60 ? 'score-high' : (r.score > 30 ? 'score-mid' : 'score-low');
                        html += `<tr><td><code>${r.mac}</code></td><td class="${scoreClass}">${r.score}</td><td>${r.vendor}</td><td>${r.reasons}</td><td>${r.ssids || ''}</td><td><button class="btn btn-safe" onclick="markSafe('${r.mac}')">Mark Safe</button></td></tr>`;
                    });
                }
                table.innerHTML = html;
            } catch (e) {
                console.error("Failed to load analysis:", e);
            }
        }

        async function loadSafeList() {
            try {
                const res = await fetch('/api/safe_list');
                const data = await res.json();
                currentRawData = data;
                const filtered = getFilteredData(data);
                renderPagination(filtered.length);
                const paged = filtered.slice((currentPage - 1) * itemsPerPage, currentPage * itemsPerPage);

                const table = document.getElementById('safe-table');
                let html = '';
                if (paged.length === 0) {
                    const msg = data.length === 0 ? 'No safe devices recorded yet.' : 'No results found with current filters.';
                    html = `<tr><td colspan="9" style="text-align:center; padding:50px; color:#888;">${msg}</td></tr>`;
                } else {
                    paged.forEach(dev => {
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
                }
                table.innerHTML = html;
            } catch (e) {
                console.error("Failed to load safe list:", e);
            }
        }

        // Improved update loop to handle slow connections
        async function runUpdateLoop() {
            try {
                if (currentTab === 'live') {
                    await updateLive();
                }
            } catch (e) {
                console.error("Update loop error:", e);
            }
            setTimeout(runUpdateLoop, 2000);
        }

        async function runSafeCacheLoop() {
            try {
                await updateSafeCache();
            } catch (e) {
                console.error("Safe cache update error:", e);
            }
            setTimeout(runSafeCacheLoop, 10000);
        }

        // Initial load
        (async function init() {
            console.log("Initializing WIFISNIFFER Dashboard...");
            try {
                await updateSafeCache();
                await updateLive();
            } catch (e) {
                console.error("Initial load error:", e);
            }
            runUpdateLoop();
            runSafeCacheLoop();
        })();
    </script>
</body>
</html>
"""

@app.route('/')
def index(): return render_template_string(HTML_TEMPLATE)

@app.route('/api/data')
def get_data():
    conn = sqlite3.connect(DB_FILE, timeout=30)
    cursor = conn.cursor()
    cursor.execute('SELECT mac, type, vendor, hits, last_seen, ssids FROM device_summary ORDER BY last_seen DESC')
    cols = [c[0] for c in cursor.description]
    data = [dict(zip(cols, r)) for r in cursor.fetchall()]
    conn.close()
    return jsonify(data)

@app.route('/api/history')
def get_history():
    mac = request.args.get('mac')
    conn = sqlite3.connect(DB_FILE, timeout=30)
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
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.execute('INSERT OR IGNORE INTO safe_devices (mac) VALUES (?)', (mac,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/api/unmark_safe', methods=['POST'])
def unmark_safe():
    mac = request.json.get('mac')
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.execute('DELETE FROM safe_devices WHERE mac = ?', (mac,))
    conn.commit()
    conn.close()
    return jsonify({"status": "success"})

@app.route('/api/safe_list')
def safe_list():
    conn = sqlite3.connect(DB_FILE, timeout=30)
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
    conn = sqlite3.connect(DB_FILE, timeout=30)
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM safe_devices WHERE mac = ?', (mac,))
    res = cursor.fetchone()
    conn.close()
    return jsonify({"safe": bool(res)})

@app.route('/api/analysis')
def get_analysis():
    conn = sqlite3.connect(DB_FILE, timeout=30)
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
    conn = sqlite3.connect(DB_FILE, timeout=30)
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
    conn = sqlite3.connect(DB_FILE, timeout=30)
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

@app.route('/api/stats')
def get_stats():
    size_bytes = os.path.getsize(DB_FILE) if os.path.exists(DB_FILE) else 0
    size_str = f"{size_bytes / (1024*1024):.2f} MB" if size_bytes > 1024*1024 else f"{size_bytes / 1024:.2f} KB"
    
    conn = sqlite3.connect(DB_FILE, timeout=30)
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM detections')
    total_detections = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM device_summary')
    total_devices = cursor.fetchone()[0]
    conn.close()
    
    return jsonify({
        "size": size_str,
        "detections": total_detections,
        "devices": total_devices
    })

@app.route('/api/maintenance/clean', methods=['POST'])
def clean_maintenance():
    conn = sqlite3.connect(DB_FILE, timeout=30)
    cursor = conn.cursor()
    # Delete detections older than 30 days
    cursor.execute("DELETE FROM detections WHERE timestamp < datetime('now', '-30 days')")
    deleted = cursor.rowcount
    
    # We don't delete from device_summary because it's a summary of all-time, 
    # but the user might want to clean inactive devices too. 
    # For now, just detections.
    
    conn.commit()
    try:
        conn.execute("VACUUM") # Reclaim space
    except sqlite3.OperationalError:
        # If the database is busy (e.g. sniffer is writing), skip VACUUM
        pass
    conn.close()
    return jsonify({"status": "success", "deleted": deleted})

@app.route('/api/export/ssid')
def export_ssid():
    ssid = request.args.get('ssid')
    if not ssid:
        return "SSID required", 400
        
    conn = sqlite3.connect(DB_FILE, timeout=30)
    cursor = conn.cursor()
    cursor.execute('SELECT timestamp, mac, type, vendor, ssid FROM detections WHERE ssid = ? ORDER BY timestamp DESC', (ssid,))
    rows = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'MAC', 'Type', 'Vendor', 'SSID'])
    writer.writerows(rows)
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename=history_{ssid}.csv"}
    )

if __name__ == "__main__":
    init_db()
    app.run(host='0.0.0.0', port=5000)
