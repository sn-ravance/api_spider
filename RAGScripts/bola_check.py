#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class BOLAScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("bola_check")
        vulnerabilities = []
        
        # Ensure URL has a scheme and host
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url.lstrip('/')
            
        parsed_url = urlparse(url)
        if not parsed_url.netloc:
            logger.error(f"Invalid URL: {url} - Missing host")
            return vulnerabilities
            
        logger.info(f"Testing endpoint: {method} {url}")
        
        # Test objects for potential BOLA vulnerabilities
        test_objects = [
            {'id': '1', 'path': 'user/1'},
            {'id': 'admin', 'path': 'user/admin'},
            {'id': 'system', 'path': 'config/system'},
            {'id': '999999', 'path': 'user/999999'}
        ]
        
        headers = {'Authorization': f'Bearer {token}'} if token else {}
        
        for test_obj in test_objects:
            try:
                # Construct test URL properly
                test_url = url.rstrip('/') + '/' + test_obj['path']
                logger.info(f"Testing object access: {test_url}")
                
                response = requests.request(
                    method,
                    test_url,
                    headers=headers,
                    timeout=5,
                    verify=False  # For testing purposes
                )
                
                # Check for potential BOLA vulnerabilities
                if response.status_code in [200, 201, 202]:
                    vuln = {
                        'type': 'BROKEN_OBJECT_LEVEL_AUTH',
                        'severity': 'HIGH',
                        'detail': f'Unauthorized access to object {test_obj["id"]} possible',
                        'evidence': {
                            'url': test_url,
                            'method': method,
                            'object_id': test_obj['id'],
                            'status_code': response.status_code,
                            'response': response.text[:200]
                        }
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"Found BOLA vulnerability: {vuln}")
                    
            except requests.RequestException as e:
                logger.error(f"Error testing object {test_obj['id']}: {str(e)}")
                continue
                
        return vulnerabilities

scan = BOLAScanner.scan

def extract_path_parameters(path: str) -> List[Dict]:
    params = []
    segments = path.split('/')
    
    for segment in segments:
        if '{' in segment and '}' in segment:
            param_name = segment.strip('{}')
            params.append({
                "name": param_name,
                "type": "id" if any(id_pattern in param_name.lower() 
                                  for id_pattern in ['id', 'uuid', 'guid']) else "other",
                "value": segment
            })
        elif segment.isdigit():
            params.append({
                "name": "id",
                "type": "id",
                "value": segment
            })
    
    return params

def generate_test_ids(original_id: str) -> List[str]:
    try:
        num_id = int(original_id)
        return [
            str(num_id + 1),
            str(num_id - 1),
            '1',
            '2',
            '999999'
        ]
    except ValueError:
        return [
            '1',
            '2',
            '999999',
            'admin',
            'test'
        ]

async def test_without_auth(session: aiohttp.ClientSession, url: str, method: str, test_id: str) -> List[Dict]:
    findings = []
    try:
        async with session.request(method, url, timeout=5) as response:
            if response.status == 200:
                findings.append({
                    "type": "API1:2023",
                    "name": "Broken Object Level Authorization",
                    "detail": f"Access to resource {test_id} without authentication",
                    "evidence": {
                        "url": url,
                        "test_id": test_id,
                        "status_code": response.status,
                        "response_length": len(await response.text())
                    },
                    "severity": "HIGH"
                })
    except:
        pass
    return findings

async def test_with_fake_auth(session: aiohttp.ClientSession, url: str, method: str, test_id: str, headers: Dict) -> List[Dict]:
    findings = []
    fake_tokens = [
        "Bearer fake_token_123",
        "Bearer invalid_token",
        "Basic YWRtaW46YWRtaW4=",
        "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Et9HFtf9R3GEMA0IICOfFMVXY7kkTX1wr4qCyhIf58U"
    ]
    
    for token in fake_tokens:
        try:
            test_headers = headers.copy()
            test_headers['Authorization'] = token
            async with session.request(method, url, headers=test_headers, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "type": "API1:2023",
                        "name": "Broken Object Level Authorization",
                        "detail": f"Access to resource {test_id} with fake token",
                        "evidence": {
                            "url": url,
                            "test_id": test_id,
                            "fake_token": token,
                            "status_code": response.status,
                            "response_length": len(await response.text())
                        },
                        "severity": "HIGH"
                    })
        except:
            continue
    return findings

async def test_horizontal_escalation(session: aiohttp.ClientSession, url: str, method: str, test_id: str, headers: Dict) -> List[Dict]:
    findings = []
    try:
        test_headers = headers.copy()
        if 'Authorization' in test_headers:
            async with session.request(method, url, headers=test_headers, timeout=5) as response:
                if response.status == 200:
                    findings.append({
                        "type": "API1:2023",
                        "name": "Broken Object Level Authorization",
                        "detail": f"Potential horizontal privilege escalation to resource {test_id}",
                        "evidence": {
                            "url": url,
                            "test_id": test_id,
                            "original_auth": test_headers.get('Authorization', ''),
                            "status_code": response.status,
                            "response_length": len(await response.text())
                        },
                        "severity": "HIGH"
                    })
    except:
        pass
    return findings

if __name__ == "__main__":
    async def test():
        result = await check_bola(
            "http://localhost:5000",
            "/api/users/1",
            "GET",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())