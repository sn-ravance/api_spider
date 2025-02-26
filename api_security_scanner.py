#!/usr/bin/env python3
"""
api_security_scanner.py

An enhanced API security scanner that performs comprehensive vulnerability assessments
on API endpoints defined in an OpenAPI specification file. It integrates various security
modules to detect common API vulnerabilities and security misconfigurations.

Features:
1. OpenAPI specification parsing
2. Comprehensive security scanning
3. Multiple vulnerability detection modules
4. Detailed security reporting
5. Asynchronous scanning capabilities
"""

import yaml
import asyncio
from typing import Dict, List, Any, Optional
import importlib
import inspect
from urllib.parse import urljoin
import requests
import logging
import json
import time

# Import security check modules
from RAGScripts.RAG_SQLi import SQLiScanner
from RAGScripts.RAG_unauthorized_password_change import UnauthorizedPasswordChangeScanner
from RAGScripts.RAG_BOLA import BOLAScanner
from RAGScripts.RAG_MassAssign import MassAssignmentScanner
from RAGScripts.RAG_Leak import DataExposureScanner
from RAGScripts.RAG_UserPass import UserPassEnumScanner
from RAGScripts.RAG_RegexDoS import RegexDOSScanner
from RAGScripts.RAG_Rate import RateLimitScanner
from RAGScripts.RAG_jwt_bypass import JWTBypassScanner

def setup_logging(verbosity: int = 1) -> logging.Logger:
    """Configure logging based on verbosity level"""
    logger = logging.getLogger('api_security_scanner')
    
    # Set logging level based on verbosity
    if verbosity == 1:
        level = logging.INFO
    elif verbosity == 2:
        level = logging.DEBUG
    elif verbosity >= 3:
        level = logging.DEBUG  # Maximum detail
    else:
        level = logging.WARNING
    
    # Configure handler with custom format
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(level)
    
    return logger

class APISecurityScanner:
    def __init__(self, spec_file: str, target_url: str, verbosity: int = 1):
        self.spec_file = spec_file
        self.target_url = target_url
        self.logger = setup_logging(verbosity)
        self.spec = self._load_spec()
        self.discovery_cache = {}
        self.security_checks = [
            SQLiScanner,
            UnauthorizedPasswordChangeScanner,
            BOLAScanner,
            MassAssignmentScanner,
            DataExposureScanner,
            UserPassEnumScanner,
            RegexDOSScanner,
            RateLimitScanner,
            JWTBypassScanner
        ]

    def _load_spec(self) -> Dict:
        """Load and parse the OpenAPI specification file."""
        try:
            with open(self.spec_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            self.logger.error(f"Error loading OpenAPI spec: {str(e)}")
            raise

    async def scan_endpoint(self, path: str, methods: Dict[str, Any]) -> List[Dict]:
        findings = []
        endpoint_url = urljoin(self.target_url, path)

        for method, details in methods.items():
            self.logger.info(f"Scanning endpoint: {method} {endpoint_url}")
            
            # Make initial request to endpoint
            try:
                response = requests.request(method, endpoint_url)
                
                # Run security checks
                for check in self.security_checks:
                    try:
                        # Create scanner instance if it's a class
                        if isinstance(check, type):
                            scanner = check()
                            check_findings = scanner.scan(endpoint_url, method, path, response)
                        else:
                            # Function-based scanner
                            check_findings = check(endpoint_url, method, path, response)
                            
                        if check_findings:
                            findings.extend(check_findings)
                    except Exception as e:
                        self.logger.error(f"Error in security check {check.__name__ if hasattr(check, '__name__') else type(check).__name__}: {str(e)}")
                        continue
                        
            except requests.RequestException as e:
                self.logger.error(f"Error accessing endpoint {endpoint_url}: {str(e)}")
                continue

        return findings

    async def scan_api(self) -> List[Dict]:
        """Scan all endpoints defined in the OpenAPI spec"""
        all_findings = []
        paths = self.spec.get('paths', {})

        for path, methods in paths.items():
            try:
                findings = await self.scan_endpoint(path, methods)
                all_findings.extend(findings)
            except Exception as e:
                self.logger.error(f"Error scanning path {path}: {str(e)}")
                continue

        return all_findings

    def run(self) -> List[Dict]:
        """Execute the security scan"""
        start_time = time.time()
        self.logger.info(f"Starting security scan of {self.target_url}")

        try:
            findings = asyncio.run(self.scan_api())
            elapsed = time.time() - start_time
            self.logger.info(f"Scan completed in {elapsed:.2f}s with {len(findings)} findings")
            return findings

        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            raise

if __name__ == "__main__":
    import sys
    import argparse

    parser = argparse.ArgumentParser(description="API Security Scanner")
    parser.add_argument("-v", "--verbose", type=int, default=1, choices=[1, 2, 3],
                        help="Verbosity level (1-3)")
    parser.add_argument("-o", "--output", help="Output file for scan results")
    parser.add_argument("spec_file", help="OpenAPI specification file")
    parser.add_argument("target_url", help="Target API URL to scan")

    args = parser.parse_args()

    scanner = APISecurityScanner(args.spec_file, args.target_url, args.verbose)
    findings = scanner.run()

    # Output findings
    output_json = json.dumps(findings, indent=2)
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output_json)
    else:
        print(output_json)