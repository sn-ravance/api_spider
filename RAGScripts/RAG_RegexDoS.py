#!/usr/bin/env python3
"""
Regex-based Denial of Service (RegexDoS) Test Script
Checks if an API endpoint is vulnerable to RegexDoS attacks
by sending specially crafted payloads to trigger regex processing delays.
"""

import requests
import time
from typing import Dict, List, Optional
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class RegexDOSScanner(BaseScanner):
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("regex_dos")
        vulnerabilities = []
        
        # Craft a malicious payload (long string that might stress regexes)
        payload = "a" * 1000 + "!"
        test_url = f"{url}/books/v1/{payload}"
        
        try:
            start_time = time.time()
            response = requests.get(test_url, timeout=60)
            end_time = time.time()
            elapsed = end_time - start_time
            
            # If the response takes an unusually long time, flag potential RegexDoS vulnerability
            if elapsed > 10:  # Threshold can be adjusted as needed
                vulnerabilities.append({
                    "type": "REGEX_DOS",
                    "severity": "HIGH",
                    "detail": f"Potential RegexDoS vulnerability detected. Request took {elapsed:.2f} seconds",
                    "evidence": {
                        "url": test_url,
                        "payload": payload,
                        "response_time": elapsed,
                        "response_code": response.status_code,
                        "response_body": response.text
                    }
                })
                
        except requests.RequestException as e:
            self.logger.error(f"Error in RegexDoS check: {str(e)}")
            
        return vulnerabilities

scan = RegexDOSScanner.scan
