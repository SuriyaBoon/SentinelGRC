"""Optional X.509 path-verification adapter."""
from dataclasses import dataclass
from cryptography import x509
from cryptography.x509 import DNSName
from cryptography.x509.verification import PolicyBuilder, Store
from crypto_agility import CryptoPolicy, CryptoPolicyError
@dataclass(frozen=True)
class X509TrustConfig:
    expected_dns_name:str; trust_roots_pem:tuple[bytes,...]
    def validate(self)->None:
        if not isinstance(self.expected_dns_name,str) or not self.expected_dns_name.strip(): raise CryptoPolicyError("X.509 expected DNS name is required")
        if not self.trust_roots_pem: raise CryptoPolicyError("X.509 trust roots are required")

class X509VerificationAdapter:
    def __init__(self,policy:CryptoPolicy,config:X509TrustConfig)->None:
        policy.require_certificate_verifier("X509-PATH"); config.validate()
        try: roots=tuple(x509.load_pem_x509_certificate(v) for v in config.trust_roots_pem)
        except (TypeError,ValueError) as error: raise CryptoPolicyError("X.509 trust configuration is invalid") from error
        self.config=config; self.store=Store(roots)
    def verify(self,peer_pem:bytes,intermediates_pem:tuple[bytes,...]=())->None:
        try:
            peer=x509.load_pem_x509_certificate(peer_pem); intermediates=[x509.load_pem_x509_certificate(v) for v in intermediates_pem]
            PolicyBuilder().store(self.store).build_server_verifier(DNSName(self.config.expected_dns_name)).verify(peer,intermediates)
        except Exception as error: raise CryptoPolicyError("X.509 peer verification failed") from error