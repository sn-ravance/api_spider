#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger
from .scanner_template import ScannerTemplate

class BFLAScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("bfla_check")
        vulnerabilities = []
        
        # Ensure URL has a scheme and host
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url.lstrip('/')
            
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            logger.error(f"Invalid URL: {url} - Missing host")
            return vulnerabilities
            
        logger.info(f"Testing endpoint: {method} {url}")
        
        # Test scenarios
        scenarios = [
            {
                'name': 'Access with user role',
                'headers': {'Role': 'user'} if token else {}
            },
            {
                'name': 'Role injection attempt',
                'headers': {'Role': 'admin', 'X-Original-Role': 'user'}
            },
            {
                'name': 'Wildcard role',
                'headers': {'Role': '*'}
            },
            {
                'name': 'Alternative role header',
                'headers': {'X-Role': 'admin', 'Authorization-Role': 'admin'}
            }
        ]
        
        base_headers = {'Authorization': f'Bearer {token}'} if token else {}
        
        for scenario in scenarios:
            try:
                logger.info(f"Testing scenario: {scenario['name']}")
                headers = {**base_headers, **scenario['headers']}
                
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    timeout=5,
                    verify=False  # For testing purposes
                )
                
                # Check for potential BFLA vulnerabilities
                if response.status_code in [200, 201, 202]:
                    vuln = {
                        'type': 'BROKEN_FUNCTION_LEVEL_AUTH',
                        'severity': 'HIGH',
                        'detail': f'Potential BFLA vulnerability found with scenario: {scenario["name"]}',
                        'evidence': {
                            'url': url,
                            'method': method,
                            'scenario': scenario['name'],
                            'headers': headers,
                            'status_code': response.status_code,
                            'response': response.text[:200]
                        }
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"Found BFLA vulnerability: {vuln}")
                    
            except requests.RequestException as e:
                logger.error(f"Error testing scenario {scenario['name']}: {str(e)}")
                continue
                
        return vulnerabilities

scan = BFLAScanner.scan
from urllib.parse import urljoin
import json

async def check_bfla(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test scenarios for function level authorization
        scenarios = [
            {
                'headers': {'Role': 'user'},
                'desc': 'Access with user role'
            },
            {
                'headers': {'Role': 'admin;user'},
                'desc': 'Role injection attempt'
            },
            {
                'headers': {'Role': '*'},
                'desc': 'Wildcard role'
            },
            {
                'headers': {'X-Original-Role': 'admin'},
                'desc': 'Alternative role header'
            }
        ]
        
        for scenario in scenarios:
            try:
                response = requests.request(
                    method,
                    test_url,
                    headers={**{'Content-Type': 'application/json'}, **scenario['headers']},
                    timeout=5
                )
                
                if is_bfla_vulnerable(response):
                    findings.append({
                        "type": "Broken Function Level Authorization",
                        "detail": f"{scenario['desc']} successful",
                        "evidence": {
                            "url": test_url,
                            "status_code": response.status_code,
                            "response": response.text[:200],
                            "headers_sent": scenario['headers']
                        }
                    })
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in BFLA check: {str(e)}")
    
    return findings

def is_bfla_vulnerable(response: requests.Response) -> bool:
    if response.status_code == 200:
        try:
            data = response.json()
            # Check for admin-only data indicators
            admin_indicators = ['admin', 'configuration', 'users', 'roles', 'permissions']
            return any(indicator in str(data).lower() for indicator in admin_indicators)
        except:
            return False
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_bfla(
            "http://localhost:5000",
            "/api/admin/users",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())