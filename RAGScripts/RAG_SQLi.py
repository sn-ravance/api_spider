
from typing import Dict, List, Optional, Any
from .base_scanner import BaseScanner
from .utils.logger import setup_scanner_logger
import requests
import time
import json

class SQLiScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("sqli")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        payloads = [
            "' OR '1'='1",
            "' AND 1=1--",
            "' AND 1=2--",
            "'; SELECT * FROM users--",
            "' UNION SELECT NULL--",
        ]
        
        for payload in payloads:
            try:
                test_resp = self.make_request(
                    method=method,
                    endpoint=path,
                    data={"username": payload, "password": payload}
                )
                
                if self.detect_sql_injection(test_resp, payload):
                    request_data, response_data = self.capture_transaction(test_resp)
                    
                    self.add_finding(
                        title="SQL Injection Vulnerability",
                        description=f"Potential Boolean-based SQL Injection detected using payload: {payload}",
                        endpoint=path,
                        severity_level="tier2",
                        impact="Unauthorized database access and manipulation",
                        request=request_data,
                        response=response_data,
                        remediation="Use parameterized queries and input validation"
                    )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing SQLi payload {payload}: {str(e)}")
                
        return self.findings
