"""Fail-closed cryptographic policy and optional adapters."""
from __future__ import annotations
import importlib.util
from dataclasses import dataclass
from typing import Iterable
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

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

