#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger
from urllib.parse import urljoin

class AssetManagementScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("asset_management_check")
        vulnerabilities = []
        headers = {'Authorization': f'Bearer {token}'} if token else {}
        
        # Ensure URL has a scheme
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url.lstrip('/')
            
        logger.info(f"Testing endpoint: {method} {url}")
        
        # Test paths for sensitive files and directories
        test_paths = [
            '.git',
            '.env',
            'backup',
            'temp',
            'old',
            'dev',
            'test',
            'debug'
        ]
        
        for path in test_paths:
            try:
                test_url = urljoin(url + '/', path)
                logger.info(f"Testing path: {test_url}")
                
                response = requests.request(
                    method,
                    test_url,
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code in [200, 403]:  # Consider 403 as potential finding
                    vuln = {
                        'type': 'SENSITIVE_ASSET_EXPOSURE',
                        'severity': 'HIGH',
                        'detail': f"Potentially sensitive asset discovered: {path}",
                        'evidence': {
                            'url': test_url,
                            'method': method,
                            'path_tested': path,
                            'status_code': response.status_code,
                            'response': response.text[:200]
                        }
                    }
                    vulnerabilities.append(vuln)
                    logger.warning(f"Found sensitive asset: {vuln}")
                    
            except requests.RequestException as e:
                logger.error(f"Error testing path {path}: {str(e)}")
                continue
        
        return vulnerabilities

scan = AssetManagementScanner.scan