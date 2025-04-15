# Log-Analyzer

A multithreaded Python-based security log analyzer for detecting suspicious activities such as brute force attacks, SQL injection attempts, XSS payloads, and malicious command executions.

✨ Features
🛡️ Brute Force Detection – Tracks failed SSH login attempts within a time window.

💉 SQL Injection Detection – Flags common SQLi patterns in web logs.

🔥 XSS Detection – Identifies potential XSS attacks.

💻 Malicious Command Detection – Catches suspicious shell command executions.

📈 Multi-threaded Processing – Efficient for large log files.

📝 Text Report Generator – Outputs a clear report of findings.

📧 Email Alert System – Optional email alerts for critical events.

🗃️ SQLite Logging – Stores detected events in a local database.
