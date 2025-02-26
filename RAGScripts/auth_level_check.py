#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger
from urllib.parse import urljoin

class AuthLevelScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("auth_level_check")
        vulnerabilities = []
        headers = {'Authorization': f'Bearer {token}'} if token else {}
        
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url.lstrip('/')
            
        logger.info(f"Testing endpoint: {method} {url}")
        
        # Test different privilege levels
        admin_endpoints = [
            {'path': 'admin', 'role': 'admin'},
            {'path': 'manage', 'role': 'manager'},
            {'path': 'console', 'role': 'admin'},
            {'path': 'dashboard', 'role': 'admin'},
            {'path': 'settings', 'role': 'admin'}
        ]
        
        for endpoint in admin_endpoints:
            try:
                test_url = urljoin(url + '/', endpoint['path'])
                logger.info(f"Testing admin endpoint: {test_url}")
                
                response = requests.request(method, test_url, headers=headers, timeout=5)
                
                if response.status_code == 200:
                    vuln = {
                        'type': 'AUTH_LEVEL_BYPASS',
                        'severity': 'HIGH',
                        'detail': f"Unauthorized access to {endpoint['role']} endpoint",
                        'evidence': {
                            'url': test_url,
                            'method': method,
                            'required_role': endpoint['role'],
                            'status_code': response.status_code,
                            'response': response.text[:200]
                        }
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"Found privilege escalation vulnerability: {vuln}")
                    
            except requests.RequestException as e:
                logger.error(f"Error testing endpoint /{endpoint['path']}: {str(e)}")
                continue
        
        # Test IDOR
        test_ids = ['123', 'admin_123', '../admin', '00000']
        for test_id in test_ids:
            try:
                test_url = urljoin(url + '/', test_id)
                logger.info(f"Testing IDOR with ID: {test_id}")
                
                response = requests.request(method, test_url, headers=headers, timeout=5)
                
                if response.status_code == 200:
                    vuln = {
                        'type': 'IDOR',
                        'severity': 'HIGH',
                        'detail': 'Insecure Direct Object Reference detected',
                        'evidence': {
                            'url': test_url,
                            'test_id': test_id,
                            'status_code': response.status_code,
                            'response': response.text[:200]
                        }
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"Found IDOR vulnerability: {vuln}")
                    
            except requests.RequestException as e:
                logger.error(f"Error testing IDOR {test_id}: {str(e)}")
                continue
        
        return vulnerabilities

scan = AuthLevelScanner.scan