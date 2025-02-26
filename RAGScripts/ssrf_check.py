#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
import socket
from urllib.parse import urlparse, urljoin
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class SSRFScanner(BaseScanner):
    # Define SSRF test payloads as class variable
    ssrf_payloads = [
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://[::1]",
        "file:///etc/passwd",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://169.254.169.254/latest/user-data",
        "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Server%20Side%20Request%20Forgery/README.md",
        "dict://localhost:11211/stat"
    ]

    @staticmethod
    def scan(url: str, method: str, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("ssrf_check")
        vulnerabilities = []
        
        # Use class variable for payloads
        for test_url in SSRFScanner.ssrf_payloads:
            try:
                # Create test vector without headers
                vector = {
                    'params': {'url': test_url},
                    'data': json.dumps({'url': test_url}),
                    'timeout': 5
                }
                
                response = requests.request(
                    method,
                    url,
                    headers=headers,  # Pass headers directly
                    **vector  # Pass other parameters through vector
                )
                
                if is_ssrf_vulnerable(response, test_url):
                    vuln = {
                        'type': 'SSRF',
                        'severity': 'HIGH',
                        'detail': f'Potential SSRF vulnerability with {test_url}',
                        'evidence': {
                            'url': url,
                            'method': method,
                            'test_url': test_url,
                            'status_code': response.status_code,
                            'response': response.text[:500]
                        }
                    }
                    vulnerabilities.append(vuln)
                    
            except requests.RequestException as e:
                logger.error(f"Error testing {test_url}: {str(e)}")
                
        return vulnerabilities

scan = SSRFScanner.scan