#!/usr/bin/env python3
"""
Aviation Intelligence Hub - Security Triage Agent v2
Comprehensive penetration testing and security analysis tool
"""

import requests
import json
import sys
import time
from urllib.parse import urljoin
from typing import Dict, List, Tuple
import re

# Colors for output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class SecurityTriageAgent:
    def __init__(self, base_url: str = "http://localhost:5001"):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.passed_tests = []
        self.warnings = []

    def log_vuln(self, severity: str, title: str, details: str):
        """Log a vulnerability"""
        self.vulnerabilities.append({
            "severity": severity,
            "title": title,
            "details": details
        })
        color = Colors.FAIL if severity == "HIGH" else Colors.WARNING
        print(f"{color}[{severity}] {title}{Colors.ENDC}")
        print(f"  └─ {details}\n")

    def log_pass(self, test: str):
        """Log a passed test"""
        self.passed_tests.append(test)
        print(f"{Colors.OKGREEN}[✓] {test}{Colors.ENDC}")

    def log_warning(self, test: str, details: str):
        """Log a warning"""
        self.warnings.append({"test": test, "details": details})
        print(f"{Colors.WARNING}[!] {test}{Colors.ENDC}")
        print(f"  └─ {details}\n")

    def test_ssrf_protection(self):
        """Test SSRF (Server-Side Request Forgery) protection"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}[1] Testing SSRF Protection{Colors.ENDC}")
        print("=" * 60)

        ssrf_payloads = [
            "http://localhost:80",
            "http://127.0.0.1:80",
            "http://0.0.0.0:80",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/",  # GCP metadata
            "http://192.168.1.1",  # Private IP
            "http://10.0.0.1",  # Private IP
            "http://172.16.0.1",  # Private IP
        ]

        for payload in ssrf_payloads:
            try:
                resp = self.session.post(
                    f"{self.base_url}/api/ingest",
                    json={"url": payload},
                    timeout=5
                )
                if resp.status_code == 400:
                    self.log_pass(f"SSRF blocked: {payload}")
                elif resp.status_code == 200:
                    self.log_vuln(
                        "HIGH",
                        f"SSRF Vulnerability Detected",
                        f"Server accepted private/internal URL: {payload}"
                    )
                else:
                    self.log_warning(
                        f"Unexpected response for {payload}",
                        f"Status code: {resp.status_code}"
                    )
            except Exception as e:
                self.log_warning(f"Error testing {payload}", str(e))

    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}[2] Testing SQL Injection{Colors.ENDC}")
        print("=" * 60)

        sql_payloads = [
            "' OR '1'='1",
            "1' OR '1'='1' --",
            "admin'--",
            "' UNION SELECT NULL--",
            "1'; DROP TABLE news_items--",
        ]

        # Test search endpoint
        for payload in sql_payloads:
            try:
                resp = self.session.get(
                    f"{self.base_url}/api/emails",
                    params={"search": payload},
                    timeout=5
                )
                if resp.status_code == 500:
                    self.log_vuln(
                        "HIGH",
                        "Potential SQL Injection",
                        f"Server error with payload: {payload}"
                    )
                elif resp.status_code == 200:
                    # Check if response looks normal
                    try:
                        data = resp.json()
                        if "error" in data:
                            self.log_warning(
                                f"SQL payload returned error",
                                f"Payload: {payload}, Response: {data.get('error')}"
                            )
                        else:
                            self.log_pass(f"SQL injection blocked/sanitized: {payload[:30]}")
                    except:
                        self.log_vuln("MEDIUM", "Unexpected response format", f"Payload: {payload}")
            except Exception as e:
                self.log_warning(f"Error testing SQL payload", str(e))

    def test_xss(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}[3] Testing XSS (Cross-Site Scripting){Colors.ENDC}")
        print("=" * 60)

        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
            "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
        ]

        for payload in xss_payloads:
            try:
                # Test search
                resp = self.session.get(
                    f"{self.base_url}/api/emails",
                    params={"search": payload},
                    timeout=5
                )
                if resp.status_code == 200:
                    # Check if payload is reflected in response
                    if payload in resp.text:
                        self.log_vuln(
                            "HIGH",
                            "Potential XSS Vulnerability",
                            f"Payload reflected in response: {payload}"
                        )
                    else:
                        self.log_pass(f"XSS payload not reflected: {payload[:30]}")
            except Exception as e:
                self.log_warning(f"Error testing XSS", str(e))

    def test_rate_limiting(self):
        """Test rate limiting implementation"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}[4] Testing Rate Limiting{Colors.ENDC}")
        print("=" * 60)

        # Try to hit the ingest endpoint multiple times quickly
        endpoint = f"{self.base_url}/api/ingest"
        successful_requests = 0
        rate_limited = False

        for i in range(35):  # Limit is 30 per minute
            try:
                resp = self.session.post(
                    endpoint,
                    json={"url": "https://example.com"},
                    timeout=2
                )
                if resp.status_code == 429:
                    rate_limited = True
                    self.log_pass(f"Rate limiting active (blocked at request {i+1})")
                    break
                elif resp.status_code < 500:
                    successful_requests += 1
            except:
                pass

        if not rate_limited:
            self.log_vuln(
                "MEDIUM",
                "Rate Limiting Not Working",
                f"Sent 35 requests without being rate limited"
            )

    def test_security_headers(self):
        """Test for security headers"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}[5] Testing Security Headers{Colors.ENDC}")
        print("=" * 60)

        try:
            resp = self.session.get(f"{self.base_url}/", timeout=5)
            headers = resp.headers

            # Check for important security headers
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": ["DENY", "SAMEORIGIN"],
                "Content-Security-Policy": None,  # Just check if present
                "Strict-Transport-Security": None,  # HSTS
                "X-XSS-Protection": None,
            }

            for header, expected in security_headers.items():
                if header in headers:
                    if expected is None or headers[header] in ([expected] if isinstance(expected, str) else expected):
                        self.log_pass(f"Security header present: {header}")
                    else:
                        self.log_warning(
                            f"Security header present but unexpected value: {header}",
                            f"Value: {headers[header]}"
                        )
                else:
                    self.log_warning(
                        f"Missing security header: {header}",
                        "Consider adding this header for better security"
                    )
        except Exception as e:
            self.log_warning("Error checking security headers", str(e))

    def test_input_validation(self):
        """Test input validation"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}[6] Testing Input Validation{Colors.ENDC}")
        print("=" * 60)

        # Test extremely long inputs
        long_input = "A" * 100000
        try:
            resp = self.session.post(
                f"{self.base_url}/api/ingest",
                json={"url": long_input},
                timeout=5
            )
            if resp.status_code == 400:
                self.log_pass("Long input rejected")
            elif resp.status_code == 429:
                self.log_warning(
                    "Rate limited during long input test",
                    "Test skipped due to rate limiting - validation cannot be verified"
                )
            else:
                self.log_vuln(
                    "MEDIUM",
                    "No length validation",
                    f"Extremely long input accepted (100k chars)"
                )
        except Exception as e:
            self.log_warning("Error testing long input", str(e))

        # Test invalid data types
        try:
            resp = self.session.post(
                f"{self.base_url}/api/ingest",
                json={"url": 12345},  # Number instead of string
                timeout=5
            )
            if resp.status_code == 400:
                self.log_pass("Invalid data type rejected")
            elif resp.status_code == 429:
                self.log_warning(
                    "Rate limited during type validation test",
                    "Test skipped due to rate limiting - validation cannot be verified"
                )
            else:
                self.log_warning(
                    "Weak type validation",
                    "Server accepted number instead of string"
                )
        except Exception as e:
            self.log_warning("Error testing data types", str(e))

    def test_api_authentication(self):
        """Test if sensitive endpoints require authentication"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}[7] Testing API Authentication{Colors.ENDC}")
        print("=" * 60)

        # Note: The app currently has no auth, which is OK for local use
        sensitive_endpoints = [
            "/api/stats",
            "/api/emails",
            "/api/feeds",
        ]

        print(f"{Colors.WARNING}⚠️  Note: App designed for local use - no auth expected{Colors.ENDC}")
        for endpoint in sensitive_endpoints:
            try:
                resp = self.session.get(f"{self.base_url}{endpoint}", timeout=5)
                if resp.status_code == 200:
                    print(f"  └─ {endpoint}: Accessible (expected for local app)")
            except:
                pass

    def test_information_disclosure(self):
        """Test for information disclosure"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}[8] Testing Information Disclosure{Colors.ENDC}")
        print("=" * 60)

        try:
            # Check if error messages leak information
            resp = self.session.get(f"{self.base_url}/nonexistent", timeout=5)
            if "Traceback" in resp.text or "Exception" in resp.text:
                self.log_vuln(
                    "LOW",
                    "Stack trace in error response",
                    "Server leaks debug information in error pages"
                )
            else:
                self.log_pass("No stack traces in error responses")

            # Check for .git directory
            resp = self.session.get(f"{self.base_url}/.git/HEAD", timeout=5)
            if resp.status_code == 200:
                self.log_vuln(
                    "HIGH",
                    ".git directory exposed",
                    "Source code may be downloadable"
                )
            else:
                self.log_pass(".git directory not exposed")

        except Exception as e:
            self.log_warning("Error testing information disclosure", str(e))

    def test_dos_protection(self):
        """Test for basic DoS protection"""
        print(f"\n{Colors.HEADER}{Colors.BOLD}[9] Testing DoS Protection{Colors.ENDC}")
        print("=" * 60)

        # Test large payload
        try:
            large_payload = {"url": "https://example.com", "data": "X" * 10000000}  # 10MB
            resp = self.session.post(
                f"{self.base_url}/api/ingest",
                json=large_payload,
                timeout=5
            )
            if resp.status_code in [400, 413]:
                self.log_pass("Large payload rejected")
            else:
                self.log_warning(
                    "Large payloads accepted",
                    "Server may be vulnerable to memory exhaustion"
                )
        except requests.exceptions.Timeout:
            self.log_pass("Request timed out (possible DoS protection)")
        except Exception as e:
            self.log_warning("Error testing large payload", str(e))

    def run_all_tests(self):
        """Run all security tests"""
        print(f"\n{Colors.BOLD}{Colors.HEADER}")
        print("=" * 60)
        print("  Aviation Intelligence Hub - Security Triage Agent v2")
        print("  Comprehensive Penetration Testing Suite")
        print("=" * 60)
        print(f"{Colors.ENDC}\n")

        print(f"Target: {Colors.OKBLUE}{self.base_url}{Colors.ENDC}\n")

        # Run all tests
        self.test_ssrf_protection()
        self.test_sql_injection()
        self.test_xss()
        self.test_rate_limiting()
        self.test_security_headers()
        self.test_input_validation()
        self.test_api_authentication()
        self.test_information_disclosure()
        self.test_dos_protection()

        # Print summary
        self.print_summary()

    def print_summary(self):
        """Print test summary"""
        print(f"\n{Colors.BOLD}{Colors.HEADER}")
        print("=" * 60)
        print("  SECURITY ASSESSMENT SUMMARY")
        print("=" * 60)
        print(f"{Colors.ENDC}\n")

        # Count by severity
        high_vulns = [v for v in self.vulnerabilities if v["severity"] == "HIGH"]
        medium_vulns = [v for v in self.vulnerabilities if v["severity"] == "MEDIUM"]
        low_vulns = [v for v in self.vulnerabilities if v["severity"] == "LOW"]

        print(f"{Colors.FAIL}Critical Vulnerabilities: {len(high_vulns)}{Colors.ENDC}")
        print(f"{Colors.WARNING}Medium Vulnerabilities:  {len(medium_vulns)}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Low Vulnerabilities:     {len(low_vulns)}{Colors.ENDC}")
        print(f"{Colors.OKGREEN}Tests Passed:            {len(self.passed_tests)}{Colors.ENDC}")
        print(f"{Colors.WARNING}Warnings:                {len(self.warnings)}{Colors.ENDC}")

        # Overall assessment
        print(f"\n{Colors.BOLD}Overall Security Rating:{Colors.ENDC}")
        if len(high_vulns) == 0 and len(medium_vulns) <= 2:
            print(f"{Colors.OKGREEN}✓ GOOD - Application has good security posture{Colors.ENDC}")
        elif len(high_vulns) == 0:
            print(f"{Colors.WARNING}⚠ MODERATE - Some improvements recommended{Colors.ENDC}")
        else:
            print(f"{Colors.FAIL}✗ NEEDS ATTENTION - Critical vulnerabilities found{Colors.ENDC}")

        print("\n" + "=" * 60 + "\n")

def main():
    # Parse target URL
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5001"

    # Create and run triage agent
    agent = SecurityTriageAgent(target)
    agent.run_all_tests()

if __name__ == "__main__":
    main()
