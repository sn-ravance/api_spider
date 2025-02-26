
#!/usr/bin/env python3
"""
Broken Object Level Authorization (BOLA) Scanner
Checks if an API endpoint is vulnerable to BOLA attacks
by attempting to access resources belonging to other users.
"""

import requests
from typing import Dict, List, Optional
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class BOLAScanner(BaseScanner):
    def scan(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("bola")
        vulnerabilities = []
        
        # Test user IDs
        test_ids = [1, 2, 3, 'admin', 'root']
        
        try:
            for test_id in test_ids:
                # Try to access user data
                user_url = f"{url}/users/v1/{test_id}"
                headers = {'Authorization': f'Bearer {token}'} if token else {}
                
                user_resp = requests.get(
                    user_url,
                    headers=headers,
                    timeout=5
                )
                
                if user_resp.status_code == 200:
                    vulnerabilities.append({
                        "type": "BOLA",
                        "severity": "HIGH",
                        "detail": f"Successfully accessed user data for ID {test_id} without proper authorization",
                        "evidence": {
                            "url": user_url,
                            "response": user_resp.json()
                        }
                    })
                    
        except requests.RequestException as e:
            self.logger.error(f"Error in BOLA check: {str(e)}")
            
        return vulnerabilities

scan = BOLAScanner.scan
