"""Test IOC validation."""
from infrastructure.analyzers.ioc.ioc_validator import IOCValidator

def test_private_ip():
    result = IOCValidator.validate('ip', '192.168.1.1')
    assert result['is_private'] == True
    assert result['risk_score'] > 0

def test_suspicious_domain():
    result = IOCValidator.validate('domain', 'malware.xyz')
    assert result['risk_score'] >= 3
    assert any('TLD' in note for note in result['notes'])

def test_valid_hash():
    result = IOCValidator.validate('hash', 'd41d8cd98f00b204e9800998ecf8427e')
    assert result['risk_score'] == 0