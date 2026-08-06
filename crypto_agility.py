"""Fail-closed cryptographic policy and optional adapters."""
from __future__ import annotations
import importlib.util
from dataclasses import dataclass
from typing import Iterable
from cryptography import x509
from cryptography.cobblestone import Cobblestone128Decryptor, Cobblestone128Encryptor, Cobblestone256Decryptor, Cobblestone256Encryptor
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import DNSName
from cryptography.x509.verification import PolicyBuilder, Store

SIGNATURE_ALGORITHMS=frozenset({"RS256","ML-DSA-44","ML-DSA-65","ML-DSA-87"})
CERTIFICATE_VERIFIERS=frozenset({"X509-PATH"})
EVIDENCE_ALGORITHMS=frozenset({"COBBLESTONE-128","COBBLESTONE-256"})

class CryptoPolicyError(ValueError): pass

def _normalized(values: Iterable[str], known: frozenset[str], area: str) -> frozenset[str]:
    result=frozenset(values)
    if any(not isinstance(v,str) or not v.strip() for v in result):
        raise CryptoPolicyError(f"{area} algorithm names must be non-empty strings")
    unknown=result-known
    if unknown: raise CryptoPolicyError(f"unknown {area} algorithms: {sorted(unknown)}")
    return result

@dataclass(frozen=True)
class CryptoCapabilities:
    mldsa: bool
    @classmethod
    def detect(cls) -> "CryptoCapabilities":
        return cls(importlib.util.find_spec("cryptography.hazmat.primitives.asymmetric.ml_dsa") is not None)

@dataclass(frozen=True)
class CryptoPolicy:
    policy_version: str="1"
    signature_algorithms: tuple[str,...]=("RS256",)
    certificate_verifiers: tuple[str,...]=()
    evidence_encryption_algorithms: tuple[str,...]=()
    def __post_init__(self) -> None:
        if not isinstance(self.policy_version,str) or not self.policy_version.strip(): raise CryptoPolicyError("crypto policy version is required")
        signatures=_normalized(self.signature_algorithms,SIGNATURE_ALGORITHMS,"signature")
        if "RS256" not in signatures: raise CryptoPolicyError("RS256 must remain enabled for the OIDC boundary")
        _normalized(self.certificate_verifiers,CERTIFICATE_VERIFIERS,"certificate")
        _normalized(self.evidence_encryption_algorithms,EVIDENCE_ALGORITHMS,"evidence encryption")
    def _require(self,name:str,enabled:Iterable[str],known:frozenset[str],area:str)->None:
        if not isinstance(name,str) or name not in known: raise CryptoPolicyError(f"unknown {area} algorithm")
        if name not in enabled: raise CryptoPolicyError(f"{area} algorithm is disabled by policy")
    def require_signature_algorithm(self,name:str)->None: self._require(name,self.signature_algorithms,SIGNATURE_ALGORITHMS,"signature")
    def require_certificate_verifier(self,name:str)->None: self._require(name,self.certificate_verifiers,CERTIFICATE_VERIFIERS,"certificate")
    def require_evidence_encryption(self,name:str)->None: self._require(name,self.evidence_encryption_algorithms,EVIDENCE_ALGORITHMS,"evidence encryption")

class RS256SignatureVerifier:
    def __init__(self,policy:CryptoPolicy)->None: self.policy=policy
    def verify(self,algorithm:str,key:rsa.RSAPublicKey,signature:bytes,message:bytes)->None:
        self.policy.require_signature_algorithm(algorithm)
        if algorithm!="RS256" or not isinstance(key,rsa.RSAPublicKey): raise CryptoPolicyError("OIDC signature verifier only accepts RS256 RSA keys")
        key.verify(signature,message,padding.PKCS1v15(),hashes.SHA256())

@dataclass(frozen=True)
class EvidenceEncryptionMetadata:
    algorithm:str; key_id:str; policy_version:str; context:bytes
    def __post_init__(self)->None:
        if not isinstance(self.key_id,str) or not self.key_id.strip() or len(self.key_id)>256: raise ValueError("evidence encryption key ID is required")
        if not self.policy_version.strip(): raise ValueError("evidence encryption policy version is required")
        if not isinstance(self.context,bytes) or not self.context or len(self.context)>1024: raise ValueError("evidence encryption context must be 1 to 1024 bytes")

class CobblestoneEvidenceCrypto:
    def __init__(self,policy:CryptoPolicy,*,algorithm:str,key:bytes|None,key_id:str,context:bytes)->None:
        policy.require_evidence_encryption(algorithm)
        expected=16 if algorithm=="COBBLESTONE-128" else 32
        if not isinstance(key,bytes) or len(key)!=expected: raise CryptoPolicyError("required evidence encryption key material is missing")
        self.key=key; self.metadata=EvidenceEncryptionMetadata(algorithm,key_id,policy.policy_version,context)
    def encrypt(self,data:bytes)->bytes:
        if not isinstance(data,bytes) or not data: raise ValueError("evidence plaintext must be non-empty bytes")
        obj=Cobblestone128Encryptor(self.key,self.metadata.context) if self.metadata.algorithm=="COBBLESTONE-128" else Cobblestone256Encryptor(self.key,self.metadata.context)
        return obj.update(data)+obj.finalize()
    def decrypt(self,data:bytes)->bytes:
        if not isinstance(data,bytes) or not data: raise ValueError("evidence ciphertext must be non-empty bytes")
        obj=Cobblestone128Decryptor(self.key,self.metadata.context) if self.metadata.algorithm=="COBBLESTONE-128" else Cobblestone256Decryptor(self.key,self.metadata.context)
        return obj.update(data)+obj.finalize()

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