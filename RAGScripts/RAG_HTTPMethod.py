#!/usr/bin/env python3
"""HTTP Method Scanner"""

from typing import Dict, List, Optional, Any
import requests
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class HTTPMethodScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("http_method")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        dangerous_methods = ["PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"]
        
        for test_method in dangerous_methods:
            try:
                test_resp = self.make_request(
                    method=test_method,
                    endpoint=path,
                    headers={"Content-Type": "application/json"}
                )
                
                if test_resp.status_code != 405:  # Method not allowed
                    request_data, response_data = self.capture_transaction(test_resp)
                    
                    self.add_finding(
                        title="Dangerous HTTP Method Enabled",
                        description=f"Endpoint allows potentially dangerous HTTP method: {test_method}",
                        endpoint=path,
                        severity_level="tier1",
                        impact="Potential for unauthorized modifications and information disclosure",
                        request=request_data,
                        response=response_data,
                        remediation="Disable unnecessary HTTP methods and implement proper method restrictions"
                    )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing HTTP method {test_method}: {str(e)}")
                
        return self.findings

scan = HTTPMethodScanner().scan