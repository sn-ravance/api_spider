
#!/usr/bin/env python3
"""BOLA (Broken Object Level Authorization) Scanner"""

from typing import Dict, List, Optional, Any
import requests
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class BOLAScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.logger = setup_scanner_logger("bola")
        
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None, headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        test_ids = ["admin", "user1", "superuser", "root"]
        original_path = path
        
        for test_id in test_ids:
            try:
                test_path = original_path.replace("{id}", test_id)
                test_resp = self.make_request(
                    method="GET",
                    endpoint=test_path
                )
                
                if test_resp.status_code == 200:
                    request_data, response_data = self.capture_transaction(test_resp)
                    
                    self.add_finding(
                        title="Broken Object Level Authorization",
                        description=f"Successfully accessed user data for ID {test_id} without proper authorization",
                        endpoint=test_path,
                        severity_level="tier2",
                        impact="Unauthorized access to user data and potential data breach",
                        request=request_data,
                        response=response_data,
                        remediation="Implement proper authorization checks for all object access"
                    )
                    
            except requests.RequestException as e:
                self.logger.error(f"Error testing BOLA with ID {test_id}: {str(e)}")
                
        return self.findings

scan = BOLAScanner().scan
