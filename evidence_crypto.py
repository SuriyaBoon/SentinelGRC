"""Optional Cobblestone evidence-encryption adapter."""
from dataclasses import dataclass
from cryptography.cobblestone import Cobblestone128Decryptor, Cobblestone128Encryptor, Cobblestone256Decryptor, Cobblestone256Encryptor
from crypto_agility import CryptoPolicy, CryptoPolicyError
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

