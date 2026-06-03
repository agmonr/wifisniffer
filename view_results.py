import sqlite3
import time
import os
import sys

DB_FILE = "discovered_macs.db"

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def view_data():
    if not os.path.exists(DB_FILE):
        print(f"[!] Database {DB_FILE} not found.")
        return

    try:
        while True:
            conn = sqlite3.connect(DB_FILE, timeout=30)
            conn.execute('PRAGMA journal_mode=WAL')
            cursor = conn.cursor()
            
            # Use the optimized summary table
            cursor.execute('''
                SELECT 
                    mac, 
                    type, 
                    vendor, 
                    hits, 
                    first_seen, 
                    last_seen, 
                    ssids
                FROM device_summary
                ORDER BY last_seen DESC
            ''')
            
            rows = cursor.fetchall()
            conn.close()

            clear_screen()
            print(f"[*] WIFISNIFFER - LIVE SUMMARY (Aggregated from raw logs)")
            print(f"[*] Database Size: {os.path.getsize(DB_FILE) / 1024:.1f} KB")
            print(f"[*] Total Unique Devices: {len(rows)}")
            print("-" * 140)
            print(f"{'MAC Address':<18} | {'Type':<12} | {'Vendor':<25} | {'Hits':<5} | {'First Seen':<20} | {'Last Seen':<20} | {'SSID(s)'}")
            print("-" * 140)
            
            for row in rows:
                mac, mtype, vendor, hits, first, last, ssids = row
                vendor_disp = vendor if vendor else "Unknown"
                ssids_disp = ssids if ssids else ""
                print(f"{mac:<18} | {mtype:<12} | {vendor_disp[:25]:<25} | {hits:<5} | {first:<20} | {last:<20} | {ssids_disp}")
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n[*] Viewer stopped.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    view_data()
