import unittest
try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from crypto_agility import CryptoCapabilities,CryptoPolicy,CryptoPolicyError,RS256SignatureVerifier
    from evidence_crypto import CobblestoneEvidenceCrypto
    from x509_verifier import X509TrustConfig,X509VerificationAdapter
except ModuleNotFoundError:
    CRYPTOGRAPHY_AVAILABLE=False
else:
    CRYPTOGRAPHY_AVAILABLE=True

@unittest.skipUnless(CRYPTOGRAPHY_AVAILABLE,"cryptography dependency is not installed")
class CryptoAgilityTests(unittest.TestCase):
    def test_default_policy_and_algorithm_confusion_fail_closed(self):
        policy=CryptoPolicy(); policy.require_signature_algorithm("RS256")
        for algorithm in ("ML-DSA-44","none","HS256"):
            with self.assertRaises(CryptoPolicyError): policy.require_signature_algorithm(algorithm)
        self.assertIsInstance(CryptoCapabilities.detect().mldsa,bool)
        with self.assertRaises(CryptoPolicyError): CryptoPolicy(signature_algorithms=("ML-DSA-44",))
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048); message=b"token"
        signature=key.sign(message,padding.PKCS1v15(),hashes.SHA256()); verifier=RS256SignatureVerifier(policy)
        verifier.verify("RS256",key.public_key(),signature,message)
        with self.assertRaises(CryptoPolicyError): verifier.verify("ML-DSA-44",key.public_key(),signature,message)
        with self.assertRaises(InvalidSignature): verifier.verify("RS256",key.public_key(),signature,b"tampered")
    def test_cobblestone_is_opt_in_and_detects_tampering(self):
        with self.assertRaises(CryptoPolicyError): CobblestoneEvidenceCrypto(CryptoPolicy(),algorithm="COBBLESTONE-128",key=b"k"*16,key_id="kv/key/1",context=b"evidence-v1")
        policy=CryptoPolicy(evidence_encryption_algorithms=("COBBLESTONE-128",))
        with self.assertRaises(CryptoPolicyError): CobblestoneEvidenceCrypto(policy,algorithm="COBBLESTONE-128",key=None,key_id="kv/key/1",context=b"evidence-v1")
        crypto=CobblestoneEvidenceCrypto(policy,algorithm="COBBLESTONE-128",key=b"k"*16,key_id="kv/key/1",context=b"evidence-v1")
        ciphertext=crypto.encrypt(b"governance evidence"); self.assertEqual(crypto.decrypt(ciphertext),b"governance evidence")
        with self.assertRaises(InvalidTag): crypto.decrypt(ciphertext[:-1]+bytes([ciphertext[-1]^1]))
    def test_x509_requires_policy_and_valid_trust_material(self):
        config=X509TrustConfig("connector.internal",())
        with self.assertRaises(CryptoPolicyError): X509VerificationAdapter(CryptoPolicy(),config)
        enabled=CryptoPolicy(certificate_verifiers=("X509-PATH",))
        with self.assertRaises(CryptoPolicyError): X509VerificationAdapter(enabled,config)
        with self.assertRaises(CryptoPolicyError): X509VerificationAdapter(enabled,X509TrustConfig("connector.internal",(b"bad",)))
if __name__=="__main__": unittest.main()