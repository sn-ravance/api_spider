#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class AuthBypassScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("auth_check")
        vulnerabilities = []
        
        scenarios = [
            {
                'name': 'No auth token',
                'headers': {}
            },
            {
                'name': 'Empty token',
                'headers': {'Authorization': 'Bearer '}
            },
            {
                'name': 'Invalid JWT format',
                'headers': {'Authorization': 'Bearer invalid.token.here'}
            },
            {
                'name': 'SQL Injection in token',
                'headers': {'Authorization': "Bearer ' OR '1'='1"}
            }
        ]
        
        for scenario in scenarios:
            try:
                response = requests.request(
                    method,
                    url,
                    headers=scenario['headers'],
                    timeout=5,
                    verify=False
                )
                
                if response.status_code in [200, 201, 202]:
                    vuln = {
                        'type': 'MISSING_AUTHENTICATION',
                        'severity': 'HIGH',
                        'detail': 'Endpoint should require authentication',
                        'evidence': {
                            'url': url,
                            'method': method,
                            'payload': scenario['headers'],
                            'status_code': response.status_code,
                            'response': response.text[:500]
                        }
                    }
                    vulnerabilities.append(vuln)
                    
            except requests.RequestException as e:
                logger.error(f"Error in scenario {scenario['name']}: {str(e)}")
                
        return vulnerabilities

scan = AuthBypassScanner.scan