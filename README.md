# Advanced-Scanner
Web Crawling:
The scanner crawls the target URL, extracting all links, images, scripts, and form elements. It processes each discovered link and resource for vulnerabilities.

Vulnerability Detection:
The tool checks for several common vulnerabilities, including:

SQL Injection (SQLi)

Cross-Site Scripting (XSS)

Command Injection (CMD)

Cross-Site Request Forgery (CSRF

Available Options:
-t, --target: Target URL (Required)

-p, --proxy: Proxy to use (e.g., http://localhost:8080)

-w, --wordlist: Wordlist file for directory brute-forcing

-o, --output: Output file for saving the JSON report

--threads: Number of threads for parallel execution (default: 20)

--user-agent: Custom User-Agent string to use for requests

Basic scan:
python3 scanner_pro.py -t http://yoursite.com

Full Scan with Wordlist and Report:

python3 scanner_pro.py -t https://yoursite.com -w /path/to/wordlist.txt -o report.json --threads 50


