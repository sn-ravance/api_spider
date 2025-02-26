
#!/usr/bin/env python3
"""Excessive Data Exposure (Debug Endpoint) Test Script"""

import sys
import os
import re
import requests
from typing import Dict, List, Optional
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from .base_scanner import BaseScanner

class DataExposureScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.target = None
        self.base_url = None

    @staticmethod
    def scan(url: str, method: str, token: Optional[str] = None, headers: Optional[Dict] = None) -> List[Dict]:
        logger = setup_scanner_logger("data_exposure")
        vulnerabilities = []

        # List of endpoints to check for data exposure
        endpoints = [
            "/users/v1/_debug",
            "/users/v1/me",
            "/users/v1",
            "/books/v1/_debug",
            "/system/debug",
            "/api/debug"
        ]
        
        # Patterns that might indicate sensitive data
        sensitive_patterns = {
            "password": r'"password"\s*:\s*"[^"]+"',
            "token": r'"token"\s*:\s*"[^"]+"',
            "api_key": r'"api[_-]?key"\s*:\s*"[^"]+"',
            "secret": r'"secret"\s*:\s*"[^"]+"',
            "private_key": r'"private[_-]?key"\s*:\s*"[^"]+"',
            "credentials": r'"credentials"\s*:\s*\{[^\}]+\}',
            "admin_status": r'"admin"\s*:\s*(true|false)',
            "email": r'"email"\s*:\s*"[^"@]+@[^"]+"',
            "username": r'"username"\s*:\s*"[^"]+"',
            "user_data": r'"users"\s*:\s*\[.*?\]',
            "debug_data": r'"_debug".*?\{.*?\}'
        }
        
        for endpoint in endpoints:
            try:
                full_url = f"{self.base_url}{endpoint}"
                response = requests.get(full_url, timeout=5)
                
                if response.status_code == 200:
                    try:
                        json_data = response.json()
                        found_patterns = []
                        
                        for pattern_name, pattern in sensitive_patterns.items():
                            if re.search(pattern, response.text, re.IGNORECASE):
                                found_patterns.append(pattern_name)
                        
                        if found_patterns:
                            self.findings.append({
                                "type": "EXCESSIVE_DATA_EXPOSURE",
                                "severity": "HIGH",
                                "detail": f"Endpoint {endpoint} exposes sensitive data",
                                "evidence": {
                                    "url": full_url,
                                    "exposed_data_types": found_patterns,
                                    "response_sample": str(json_data)[:200]
                                }
                            })
                    except ValueError:
                        pass
                        
            except requests.RequestException as e:
                continue

    @staticmethod
    def scan(url: str, method: str, path: str, response: requests.Response) -> List[Dict]:
        scanner = DataExposureScanner()
        scanner.target = f"{url}{path}"
        scanner.base_url = url
        scanner.run()
        return scanner.findings

scan = DataExposureScanner.scan

if __name__ == "__main__":
    scanner = DataExposureScanner()
    scanner.execute()
