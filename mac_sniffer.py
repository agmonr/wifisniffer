import sys
import sqlite3
import time
from scapy.all import sniff, Dot11, Dot11Beacon, Dot11ProbeResp
from mac_vendor_lookup import MacLookup

# Configuration
DB_FILE = "discovered_macs.db"
IGNORED_SSIDS = ["virus007", "virus006", "kkk"]

# Initialize MAC lookup
print("[*] Loading MAC vendor database...")
try:
    mac_lookup = MacLookup()
except Exception:
    mac_lookup = None

# Global state
session_devices = {}
ignored_macs = set()   # MACs associated with ignored SSIDS
packet_count = 0
vendor_cache = {}
db_conn = None

def init_db():
    """Initializes the database and populates the log cooldown cache."""
    global last_log_time
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
    
    # Populate last_log_time cache from DB
    print("[*] Populating log cooldown cache from database...")
    cursor.execute('SELECT mac, strftime("%s", MAX(timestamp)) FROM detections GROUP BY mac')
    for mac, ts in cursor.fetchall():
        if ts:
            last_log_time[mac.lower()] = float(ts)
            
    conn.commit()
    conn.close()

def save_to_db(mac, mtype, vendor, ssid):
    """Logs a detection to the database using a persistent connection."""
    global db_conn
    try:
        if db_conn is None:
            db_conn = sqlite3.connect(DB_FILE, timeout=30)
            db_conn.execute('PRAGMA journal_mode=WAL')
        
        cursor = db_conn.cursor()
        cursor.execute('''
            INSERT INTO detections (mac, type, vendor, ssid)
            VALUES (?, ?, ?, ?)
        ''', (mac, mtype, vendor, ssid))
        
        # Commit every 50 packets to balance safety and performance
        if packet_count % 50 == 0:
            db_conn.commit()
    except Exception as e:
        print(f"[!] Database error: {e}")
        db_conn = None # Reset connection on error

def get_vendor(mac):
    if mac in vendor_cache: return vendor_cache[mac]
    if not mac_lookup: return "Unknown"
    try:
        v = mac_lookup.lookup(mac)
        vendor_cache[mac] = v
        return v
    except:
        vendor_cache[mac] = "Unknown"
        return "Unknown"

def print_table():
    """Live terminal display showing ALL discovered MACs."""
    print("\033c", end="")
    print(f"[*] Packets Sniffed: {packet_count}")
    print(f"[*] Unique MACs Seen: {len(session_devices)}")
    print(f"[*] Ignored Networks: {', '.join(IGNORED_SSIDS)}")
    print("-" * 100)
    print(f"{'MAC Address':<18} | {'Type':<12} | {'Vendor':<25} | {'SSID'}")
    print("-" * 100)
    for mac, info in sorted(session_devices.items(), key=lambda x: x[1]['type']):
        ssid = info['ssid'] if info['ssid'] else ""
        # Mark ignored MACs in the live view for clarity
        tag = " [IGNORED]" if mac in ignored_macs else ""
        print(f"{mac:<18} | {info['type']:<12} | {info['vendor'][:25]:<25} | {ssid}{tag}")

def packet_handler(pkt):
    global packet_count
    packet_count += 1

    if not pkt.haslayer(Dot11):
        if packet_count % 100 == 0: print_table()
        return

    # Identify SSID and map it to the AP MAC
    packet_ssid = None
    if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
        try:
            packet_ssid = pkt.info.decode('utf-8', errors='ignore')
            if not packet_ssid: packet_ssid = "<Hidden SSID>"
        except: pass
        
        # If this is one of our ignored networks, mark the AP (addr2/addr3) as ignored
        if packet_ssid in IGNORED_SSIDS:
            if pkt.addr2: ignored_macs.add(pkt.addr2.lower())
            if pkt.addr3: ignored_macs.add(pkt.addr3.lower())

    addrs = [pkt.addr1, pkt.addr2, pkt.addr3]
    new_discovery = False

    for addr in addrs:
        if not addr or addr == "ff:ff:ff:ff:ff:ff": continue
        addr = addr.lower()
        
        vendor = get_vendor(addr)
        mtype = "Access Point" if packet_ssid else "Device"
        
        # 1. Update Session Memory (Always show in live view)
        if addr not in session_devices:
            session_devices[addr] = {"vendor": vendor, "ssid": packet_ssid, "type": mtype}
            new_discovery = True
        elif packet_ssid and session_devices[addr]["ssid"] != packet_ssid:
            session_devices[addr]["ssid"] = packet_ssid
            session_devices[addr]["type"] = "Access Point"
            new_discovery = True

        # 2. Persist to DB ONLY if the MAC is not in our ignored list
        # We also check addr3 (BSSID) for the current packet to catch connected clients
        is_ignored_packet = (pkt.addr3 and pkt.addr3.lower() in ignored_macs) or (addr in ignored_macs)
        
        if not is_ignored_packet:
            save_to_db(addr, mtype, vendor, packet_ssid)

    if new_discovery or packet_count % 50 == 0:
        print_table()

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)
        
    init_db()
    print(f"[*] Sniffing on {sys.argv[1]}...")
    try:
        sniff(iface=sys.argv[1], prn=packet_handler, store=0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
 
    init_db()
    print(f"[*] Sniffing on {sys.argv[1]}...")
    try:
        sniff(iface=sys.argv[1], prn=packet_handler, store=0)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
