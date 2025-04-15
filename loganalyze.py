import re
import smtplib
from collections import defaultdict, deque
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from threading import Thread
import queue
import sqlite3
import argparse

class LogAnalyzer:
    def __init__(self):
        self.suspicious_activities = []
        self.failed_logins = defaultdict(deque)
        self.ip_activity = defaultdict(int)
        self.BRUTE_FORCE_THRESHOLD = 3
        self.BRUTE_FORCE_WINDOW = 100
        self.PORT_SCAN_THRESHOLD = 10
        
    def analyze_line(self, log_line):
        try:
            log_line_lower = log_line.lower()
            if any(x in log_line_lower for x in ["failed password", "authentication failure"]):
                self._detect_brute_force(log_line)
            if self._detect_sql_injection(log_line):
                self.suspicious_activities.append(("SQL Injection Attempt", log_line))
            if self._detect_xss(log_line):
                self.suspicious_activities.append(("XSS Attempt", log_line))
            if self._detect_malicious_commands(log_line):
                self.suspicious_activities.append(("Malicious Command Execution", log_line))
            if self._detect_port_scan(log_line):
                ip = self._extract_ip(log_line)
                if ip != "UNKNOWN_IP":
                    self.ip_activity[ip] += 1
                    if self.ip_activity[ip] >= self.PORT_SCAN_THRESHOLD:
                        self.suspicious_activities.append(("Port Scanning Activity", log_line))
        except Exception as e:
            print(f"Error processing line: {log_line.strip()}\nError: {str(e)}")
    
    def _parse_log_time(self, log_line):
        try:
            match = re.match(r'^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})', log_line)
            if match:
                log_time_str = match.group(1)
                log_time = datetime.strptime(log_time_str, "%b %d %H:%M:%S")
                return log_time.replace(year=datetime.now().year)
        except Exception as e:
            print(f"[!] Failed to parse time: {e}")
        return datetime.now()

    def _extract_ip(self, log_line):
        ip_patterns = [
            r'Failed password for .* from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) port \d+',
            r'authentication failure; .* rhost=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'client (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'(?<!\d)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!\d)'
        ]
        for pattern in ip_patterns:
            match = re.search(pattern, log_line)
            if match:
                return match.group(1)
        return None

    def _detect_brute_force(self, log_line):
        if not any(x in log_line.lower() for x in ["failed password", "authentication failure"]):
            return
        ip = self._extract_ip(log_line)
        if ip is None:
            return
        now = self._parse_log_time(log_line)
        if ip not in self.failed_logins:
            self.failed_logins[ip] = deque(maxlen=20)
        while (self.failed_logins[ip] and 
            (now - self.failed_logins[ip][0]).total_seconds() > self.BRUTE_FORCE_WINDOW):
            self.failed_logins[ip].popleft()
        self.failed_logins[ip].append(now)
        current_attempts = len(self.failed_logins[ip])
        print(f"[DEBUG] {ip} failed at {now}, total={current_attempts}")
        if current_attempts == self.BRUTE_FORCE_THRESHOLD - 1:
            print(f"Warning: IP {ip} approaching threshold with {current_attempts} attempts")
        if current_attempts >= self.BRUTE_FORCE_THRESHOLD:
            time_window = min(
                (now - self.failed_logins[ip][0]).total_seconds(),
                self.BRUTE_FORCE_WINDOW
            )
            alert_msg = (f"Brute Force Detected: {ip} made {current_attempts} "
                        f"failed attempts in {time_window:.1f} seconds")
            self.suspicious_activities.append((alert_msg, log_line))
            print(f"ALERT: {alert_msg}")
            self.failed_logins[ip].clear()
        
    def _detect_sql_injection(self, log_line):
        sql_patterns = [
            r'union\s+select',
            r'select.*from',
            r'insert\s+into',
            r'drop\s+table',
            r'1=1',
            r';--',
            r'exec\(',
            r'xp_cmdshell'
        ]
        return any(re.search(pattern, log_line, re.IGNORECASE) for pattern in sql_patterns)
    
    def _detect_xss(self, log_line):
        xss_patterns = [
            r'<script>',
            r'javascript:',
            r'onerror=',
            r'onload=',
            r'alert\(',
            r'document\.cookie'
        ]
        return any(re.search(pattern, log_line, re.IGNORECASE) for pattern in xss_patterns)
    
    def _detect_malicious_commands(self, log_line):
        malicious_cmds = [
            "rm -rf", "wget", "curl", 
            "chmod 777", "nc -l", "/bin/bash",
            "sh -i", "mkfifo", "python -c",
            "perl -e", "php -r"
        ]
        log_line_lower = log_line.lower()
        return any(cmd in log_line_lower for cmd in malicious_cmds)
    
    def _detect_port_scan(self, log_line):
        port_scan_indicators = [
            "connection refused",
            "connection reset",
            "closed",
            "failed to connect",
            "port scan"
        ]
        log_line_lower = log_line.lower()
        return any(indicator in log_line_lower for indicator in port_scan_indicators)

def process_chunk(chunk, result_queue):
    analyzer = LogAnalyzer()
    for line in chunk:
        analyzer.analyze_line(line)
    result_queue.put(analyzer.suspicious_activities)

def analyze_large_log(log_file, num_threads=4):
    try:
        with open(log_file) as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading log file: {str(e)}")
        return []
    chunk_size = len(lines) // num_threads
    result_queue = queue.Queue()
    threads = []
    for i in range(num_threads):
        chunk = lines[i*chunk_size : (i+1)*chunk_size]
        t = Thread(target=process_chunk, args=(chunk, result_queue))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    all_results = []
    while not result_queue.empty():
        all_results.extend(result_queue.get())
    return all_results

def analyze_large_log(log_file):
    analyzer = LogAnalyzer()
    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                analyzer.analyze_line(line)
    except Exception as e:
        print(f"Error reading log file: {str(e)}")
        return []
    return analyzer.suspicious_activities

def generate_txt_report(suspicious_activities, output_file="security_report.txt"):
    with open(output_file, "w") as f:
        f.write("=== SECURITY LOG ANALYSIS REPORT ===\n")
        f.write(f"Generated at: {datetime.now()}\n\n")
        if not suspicious_activities:
            f.write("No suspicious activities detected.\n")
            return
        f.write(f"Found {len(suspicious_activities)} suspicious events:\n\n")
        for i, (event_type, log_entry) in enumerate(suspicious_activities, 1):
            f.write(f"{i}. [{event_type}]\n")
            f.write(f"   Log Entry: {log_entry.strip()}\n\n")

def send_email_alert(subject, body, to_email, smtp_server="smtp.gmail.com", smtp_port=587):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = "security-alerts@yourdomain.com"
    msg['To'] = to_email
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login("your-email@gmail.com", "your-password")
        server.send_message(msg)

def init_db():
    conn = sqlite3.connect("security_logs.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        event_type TEXT,
        source_ip TEXT,
        log_entry TEXT
    )
    """)
    conn.commit()
    conn.close()

def log_to_db(suspicious_activities):
    conn = sqlite3.connect("security_logs.db")
    cursor = conn.cursor()
    for event_type, log_entry in suspicious_activities:
        ip = LogAnalyzer()._extract_ip(log_entry)
        cursor.execute(
            "INSERT INTO security_events (event_type, source_ip, log_entry) VALUES (?, ?, ?)",
            (event_type, ip, log_entry.strip())
        )
    conn.commit()
    conn.close()

def main():
    parser = argparse.ArgumentParser(description="Security Log Analyzer")
    parser.add_argument("logfile", help="Path to log file to analyze")
    parser.add_argument("--email", help="Email address to send alerts to")
    parser.add_argument("--report", action="store_true", help="Generate text report")
    parser.add_argument("--verbose", action="store_true", help="Show detailed output")
    args = parser.parse_args()
    print(f"Analyzing log file: {args.logfile}")
    suspicious_activities = analyze_large_log(args.logfile)
    if suspicious_activities:
        print(f"\n[!] Found {len(suspicious_activities)} suspicious events:")
        for i, (event_type, log_entry) in enumerate(suspicious_activities, 1):
            print(f"{i}. {event_type}")
            if args.verbose:
                print(f"   {log_entry.strip()}")
        if args.email:
            try:
                email_body = "\n".join([f"{et}: {le}" for et, le in suspicious_activities])
                send_email_alert(
                    "Security Alert: Suspicious Activity Detected",
                    email_body,
                    args.email
                )
                print(f"\n[+] Alert sent to {args.email}")
            except Exception as e:
                print(f"\n[!] Failed to send email: {str(e)}")
        if args.report:
            generate_txt_report(suspicious_activities)
            print("\n[+] Generated security_report.txt")
        init_db()
        log_to_db(suspicious_activities)
        print("[+] Logged events to security_logs.db")
    else:
        print("\n[+] No suspicious activities detected")

if __name__ == "__main__":
    main()