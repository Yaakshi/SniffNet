import sqlite3
import csv

def export_to_csv(db_path="traffic.db", csv_path="traffic_export.csv"):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    cur.execute("SELECT * FROM packets")
    rows = cur.fetchall()
    columns = [desc[0] for desc in cur.description]

    with open(csv_path, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(columns)
        writer.writerows(rows)

    conn.close()
    print(f"[+] Exported {len(rows)} records to {csv_path}")

if __name__ == "__main__":
    export_to_csv()
