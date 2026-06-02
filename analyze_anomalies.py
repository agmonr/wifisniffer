import sqlite3
import pandas as pd
import os
import numpy as np

DB_FILE = "discovered_macs.db"
SESSION_THRESHOLD_MINS = 15  # Gaps larger than this define a new "visit"

def analyze():
    if not os.path.exists(DB_FILE):
        print("[!] Database not found.")
        return

    conn = sqlite3.connect(DB_FILE)
    try:
        # Optimization: Only get MACs seen in the last 24 hours
        cursor = conn.cursor()
        cursor.execute("SELECT mac FROM device_summary WHERE last_seen > datetime('now', '-24 hours')")
        recent_macs = [r[0] for r in cursor.fetchall()]
        
        if not recent_macs:
            print("[*] No active devices in the last 24 hours.")
            return

        placeholders = ','.join(['?'] * len(recent_macs))
        df = pd.read_sql_query(f"SELECT * FROM detections WHERE mac IN ({placeholders})", conn, params=recent_macs)
    except Exception as e:
        print(f"[!] Error: {e}")
        return
    finally:
        conn.close()

    if df.empty:
        print("[*] No data found.")
        return

    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['hour'] = df['timestamp'].dt.hour
    df['date'] = df['timestamp'].dt.date
    
    results = []
    
    unique_macs = df['mac'].unique()
    for mac in unique_macs:
        m_data = df[df['mac'] == mac].sort_values('timestamp')
        
        reasons = []
        score = 0
        
        # --- 1. SESSION / VISIT ANALYSIS (Coming and Going) ---
        # Calculate time diffs between consecutive detections
        m_data['diff'] = m_data['timestamp'].diff().dt.total_seconds() / 60
        # A new session starts if the gap is > threshold
        m_data['new_session'] = m_data['diff'] > SESSION_THRESHOLD_MINS
        m_data['session_id'] = m_data['new_session'].cumsum()
        
        sessions = m_data.groupby('session_id').agg(
            start=('timestamp', 'min'),
            end=('timestamp', 'max'),
            count=('id', 'count')
        )
        sessions['duration_mins'] = (sessions['end'] - sessions['start']).dt.total_seconds() / 60
        
        num_visits = len(sessions)
        avg_duration = sessions['duration_mins'].mean()
        
        if num_visits >= 2:
            reasons.append(f"Mobile Pattern ({num_visits} separate visits, avg {avg_duration:.1f}m each)")
            score += 25 * min(num_visits, 4) # Caps at 100 for many visits

        # --- 2. TIME CLUSTERING (Specific Hours) ---
        distinct_hours = m_data['hour'].unique()
        hour_range = np.ptp(distinct_hours) if len(distinct_hours) > 0 else 0
        
        # If seen multiple times but only within a narrow window of hours
        if len(m_data) > 20 and hour_range <= 2 and hour_range >= 0:
            # Check if this is across multiple days or just one short stay
            num_days = m_data['date'].nunique()
            if num_days >= 1:
                reasons.append(f"Time Clustered (Always seen in a {hour_range+1}h window)")
                score += 20

        # --- 3. NIGHT ACTIVITY ---
        night_hits = m_data[(m_data['hour'] >= 23) | (m_data['hour'] <= 5)]
        if len(night_hits) > 0 and (len(night_hits) / len(m_data)) > 0.7:
            reasons.append("Night Owl (primarily seen at night)")
            score += 30
            
        # --- 4. VENDOR CHECK ---
        vendor = m_data['vendor'].iloc[0]
        if vendor == "Unknown":
            reasons.append("Unknown Vendor (Generic/Randomized)")
            score += 10

        if score > 0:
            results.append({
                "mac": mac,
                "score": score,
                "vendor": vendor,
                "reasons": ", ".join(reasons),
                "visits": num_visits
            })

    print("\n" + "="*140)
    print(f"{'MAC ADDRESS':<18} | {'SCORE':<5} | {'VISITS':<6} | {'VENDOR':<20} | {'ANOMALIES'}")
    print("="*140)
    
    # Sort by score
    for r in sorted(results, key=lambda x: x['score'], reverse=True):
        print(f"{r['mac']:<18} | {r['score']:<5} | {r['visits']:<6} | {r['vendor'][:20]:<20} | {r['reasons']}")
    print("="*140)
    print(f"[*] Analysis complete. Threshold for 'Visit' is {SESSION_THRESHOLD_MINS} minutes of silence.")

if __name__ == "__main__":
    analyze()
