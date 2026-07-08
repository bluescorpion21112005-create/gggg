"""Local IOC checks and threat intelligence integration (stub)."""
import ipaddress
import re
import logging
from typing import Dict, Optional
import validators

logger = logging.getLogger(__name__)

class IOCValidator:
    """Performs local risk assessments for IOCs."""
    # Common malware TLDs (example)
    SUSPICIOUS_TLDS = {'.xyz', '.top', '.tk', '.ml', '.ga', '.cf', '.gq', '.info', '.cc'}

    @staticmethod
    def validate(ioc_type: str, value: str) -> Dict[str, any]:
        """Return a dict with 'risk_score' (0-10), 'notes', and any indicators."""
        ioc_type = ioc_type.lower()
        result = {'risk_score': 0, 'notes': [], 'is_private': False, 'is_known_malicious': False}
        try:
            if ioc_type == 'ip':
                result.update(IOCValidator._check_ip(value))
            elif ioc_type == 'domain':
                result.update(IOCValidator._check_domain(value))
            elif ioc_type == 'url':
                result.update(IOCValidator._check_url(value))
            elif ioc_type == 'hash':
                result.update(IOCValidator._check_hash(value))
            elif ioc_type == 'email':
                result.update(IOCValidator._check_email(value))
            elif ioc_type == 'filename':
                result.update(IOCValidator._check_filename(value))
            else:
                result['notes'].append(f"Unknown IOC type '{ioc_type}'.")
        except Exception as e:
            logger.warning(f"IOC validation error for {ioc_type}:{value} - {e}")
            result['notes'].append(f"Validation error: {e}")
        return result

    @staticmethod
    def _check_ip(ip: str) -> Dict:
        notes = []
        risk = 0
        is_private = False
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                is_private = True
                notes.append("This is a private IP address (RFC 1918). Not externally routable.")
                risk = max(risk, 1)  # low risk, but could indicate internal recon
            if ip_obj.is_multicast:
                notes.append("Multicast IP – unusual for C2.")
                risk += 1
            if ip_obj.is_loopback:
                notes.append("Loopback address – likely false positive.")
                risk = 0
        except ValueError:
            notes.append("Invalid IP format.")
            risk = 5
        # Placeholder: check against known malicious lists (could integrate AbuseIPDB)
        return {'risk_score': risk, 'notes': notes, 'is_private': is_private}

    @staticmethod
    def _check_domain(domain: str) -> Dict:
        notes = []
        risk = 0
        if not validators.domain(domain):
            notes.append("Invalid domain format.")
            return {'risk_score': 5, 'notes': notes}
        tld = '.' + domain.split('.')[-1] if '.' in domain else ''
        if tld.lower() in IOCValidator.SUSPICIOUS_TLDS:
            notes.append(f"TLD '{tld}' is frequently associated with malware/phishing.")
            risk += 3
        # Check for excessive entropy / random-looking subdomain
        subdomain = domain.split('.')[0] if domain.count('.') >= 2 else ''
        if len(subdomain) > 20 and re.search(r'[a-zA-Z]{3,}\d{3,}', subdomain):
            notes.append("Random-looking subdomain – possible DGA.")
            risk += 3
        # Check for typosquatting keywords? Not implemented.
        return {'risk_score': min(risk, 10), 'notes': notes}

    @staticmethod
    def _check_url(url: str) -> Dict:
        notes = []
        risk = 0
        if not validators.url(url):
            notes.append("Invalid URL format.")
            return {'risk_score': 5, 'notes': notes}
        # Check for suspicious keywords
        if any(kw in url.lower() for kw in ['/admin', '/login', '/cpanel', '/wp-admin', 'cmd=', 'exec=']):
            notes.append("URL contains sensitive paths or parameters often targeted.")
            risk += 2
        # Check domain part
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        domain_result = IOCValidator._check_domain(domain)
        risk += domain_result['risk_score'] // 2  # combine
        notes.extend(domain_result['notes'])
        return {'risk_score': min(risk, 10), 'notes': notes}

    @staticmethod
    def _check_hash(hash_str: str) -> Dict:
        notes = []
        risk = 0
        # Check hash length
        if len(hash_str) not in (32, 40, 64):
            notes.append("Hash string length does not match MD5/SHA1/SHA256.")
            risk += 2
        # Example: check if it's all zero
        if all(c == '0' for c in hash_str):
            notes.append("Hash is all zeros – likely false positive.")
            risk = 0
        # VirusTotal lookup could go here
        return {'risk_score': risk, 'notes': notes}

    @staticmethod
    def _check_email(email: str) -> Dict:
        notes = []
        risk = 0
        if not validators.email(email):
            notes.append("Invalid email format.")
            return {'risk_score': 2, 'notes': notes}
        # Check for free email domains often used by phishing
        domain = email.split('@')[-1].lower()
        if domain in ('gmail.com', 'yahoo.com', 'outlook.com', 'mail.ru'):
            notes.append(f"Free email provider ({domain}) – common in phishing campaigns.")
            risk += 2
        # Check for lookalike domains (simple)
        if 'rnicrosoft' in domain or 'micr0soft' in domain:
            notes.append("Typosquatted domain – high risk.")
            risk = 10
        return {'risk_score': min(risk, 10), 'notes': notes}

    @staticmethod
    def _check_filename(filename: str) -> Dict:
        notes = []
        risk = 0
        # Suspicious extensions
        suspicious_exts = {'.exe', '.scr', '.bat', '.ps1', '.vbs', '.js', '.jar', '.docm', '.xlsm'}
        ext = '.' + filename.rsplit('.', 1)[-1] if '.' in filename else ''
        if ext.lower() in suspicious_exts:
            notes.append(f"Executable/suspicious extension: {ext}")
            risk += 3
        # Double extension
        if filename.count('.') > 1 and ext.lower() in ('.pdf', '.docx', '.xlsx', '.zip'):
            notes.append("Double extension – possible masquerading.")
            risk += 4
        # Suspicious names
        if any(name in filename.lower() for name in ('invoice', 'payment', 'order', 'shipping', 'dhl')):
            notes.append("Filename resembles common phishing lure.")
            risk += 2
        return {'risk_score': min(risk, 10), 'notes': notes}