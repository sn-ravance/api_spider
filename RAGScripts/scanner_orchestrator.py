#!/usr/bin/env python3

from typing import Dict, List, Optional, Type
from .base_scanner import BaseScanner
from .bola_check import BOLAScanner
from .sqli_check import SQLiScanner
from .xss_check import XSSScanner
from .xxe_check import XXEScanner
from .auth_check import AuthBypassScanner
from .auth_level_check import AuthLevelScanner
from .path_traversal_check import PathTraversalScanner
from .asset_management_check import AssetManagementScanner
from .llm_analyzer import LLMAnalyzer

class ScannerOrchestrator:
    def __init__(self):
        self.scanners = [
            BOLAScanner,
            SQLiScanner,
            XSSScanner,
            XXEScanner,
            AuthBypassScanner,
            AuthLevelScanner,
            PathTraversalScanner,
            AssetManagementScanner
        ]
        self.llm_analyzer = LLMAnalyzer()
        
    async def scan_endpoint(self, url: str, method: str, path: str, response: requests.Response, token: Optional[str] = None) -> List[Dict]:
        """Run all security scanners on a single endpoint with sequential LLM analysis"""
        findings = []
        
        for scanner_class in self.scanners:
            try:
                scanner = scanner_class()
                scanner_findings = scanner.scan(url, method, path, response, token)
                
                # Process each finding sequentially with LLM analysis
                validated_findings = []
                for finding in scanner_findings:
                    # Analyze finding with LLM
                    llm_analysis = await self.llm_analyzer.analyze_finding(finding)
                    
                    # Only include findings that LLM validates as true positives
                    if llm_analysis and llm_analysis.get('confidence', 0) > 0.7:
                        finding['llm_analysis'] = llm_analysis
                        validated_findings.append(finding)
                    
                findings.extend(validated_findings)
                
            except Exception as e:
                self.logger.error(f"Error running {scanner_class.__name__}: {str(e)}")
                continue
                
        return findings

    async def scan_api(self, base_url: str, endpoints: List[Dict], token: Optional[str] = None) -> List[Dict]:
        """Scan entire API with sequential security checks and LLM analysis"""
        all_findings = []
        
        for endpoint in endpoints:
            url = base_url.rstrip('/') + '/' + endpoint['path'].lstrip('/')
            method = endpoint.get('method', 'GET')
            
            try:
                # Make initial request
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, headers={'Authorization': f'Bearer {token}'} if token else {}) as response:
                        # Run all scanners on this endpoint sequentially
                        endpoint_findings = await self.scan_endpoint(base_url, method, endpoint['path'], response, token)
                        all_findings.extend(endpoint_findings)
                
            except Exception as e:
                self.logger.error(f"Error scanning endpoint {url}: {str(e)}")
                continue
                
        return all_findings