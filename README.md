# Advanced-Scanner
Web Vulnerability Scanner Pro (Version 3.14 - Kali Edition)
This Web Vulnerability Scanner Pro is a powerful tool designed to analyze and identify vulnerabilities in websites and web applications. With various security checks, crawling features, and brute-force capabilities, this tool helps you detect critical vulnerabilities like SQL Injection, Cross-Site Scripting (XSS), Command Injection (CMD), and Cross-Site Request Forgery (CSRF), among others.

Key Features:
Web Crawling:
The scanner crawls the target URL, extracting all links, images, scripts, and form elements. It processes each discovered link and resource for vulnerabilities.

Vulnerability Detection:
The tool checks for several common vulnerabilities, including:

SQL Injection (SQLi)

Cross-Site Scripting (XSS)

Command Injection (CMD)

Cross-Site Request Forgery (CSRF)

Directory Brute-Forcing:
It uses a wordlist to attempt brute-forcing directories and files hidden on the target server. This allows you to discover sensitive paths or files that are not directly linked on the website.

SSL/TLS Certificate Analysis:
The scanner checks the SSL/TLS configuration of the target server, validating the certificate and its expiration date. It also detects misconfigurations or expired certificates, improving the security posture of the site.

Security Header Check:
The tool ensures that critical HTTP security headers like Content-Security-Policy, X-Content-Type-Options, Strict-Transport-Security, and X-Frame-Options are present to protect against various attacks.

Multi-threaded Scanning:
With multi-threading support, the scanner runs efficiently by performing parallel tasks, significantly reducing the time needed for large scans.

Custom Report Generation:
After completing the scan, the tool generates a detailed JSON report of all vulnerabilities detected, including the type of vulnerability and the corresponding affected resource.

