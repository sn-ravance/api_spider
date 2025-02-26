#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from .base_scanner import BaseScanner
from utils.logger import setup_scanner_logger

class XSSScanner(BaseScanner):
    async def scan(self, url: str, method: str, **kwargs) -> List[Dict[str, Any]]:
        # XSS scanning implementation
        findings = []
        logger = setup_scanner_logger("xss_check")
        vulnerabilities = []
        headers = {'Authorization': f'Bearer {token}'} if token else {}
        
        logger.info(f"Testing endpoint: {method} {url}")
        
        # XSS test payloads
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>'
        ]
        
        for payload in payloads:
            try:
                logger.info(f"Testing payload: {payload}")
                if method == 'GET':
                    response = requests.get(
                        url, 
                        params={'test': payload},
                        headers=headers,
                        timeout=5
                    )
                else:
                    response = requests.request(
                        method,
                        url,
                        json={'test': payload},
                        headers=headers,
                        timeout=5
                    )
                
                if payload in response.text:
                    vuln = {
                        'type': 'XSS',
                        'severity': 'HIGH',
                        'detail': 'Potential XSS vulnerability',
                        'evidence': {
                            'url': url,
                            'method': method,
                            'payload': payload,
                            'status_code': response.status_code,
                            'response': response.text[:200]
                        }
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"Found XSS vulnerability: {vuln}")
                    
            except requests.RequestException as e:
                logger.error(f"Error testing payload {payload}: {str(e)}")
                continue
                
        return vulnerabilities

scan = XSSScanner.scan