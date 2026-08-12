import unittest

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from crypto_agility import (
        CryptoCapabilities,
        CryptoPolicy,
        CryptoPolicyError,
        RS256SignatureVerifier,
    )
except ModuleNotFoundError:
    CORE_CRYPTOGRAPHY_AVAILABLE = False
else:
    CORE_CRYPTOGRAPHY_AVAILABLE = True

try:
    from cryptography.exceptions import InvalidTag
    from evidence_crypto import CobblestoneEvidenceCrypto
except (ImportError, ModuleNotFoundError):
    COBBLESTONE_AVAILABLE = False
else:
    COBBLESTONE_AVAILABLE = True

try:
    from x509_verifier import X509TrustConfig, X509VerificationAdapter
except (ImportError, ModuleNotFoundError):
    X509_VERIFICATION_AVAILABLE = False
else:
    X509_VERIFICATION_AVAILABLE = True


@unittest.skipUnless(
    CORE_CRYPTOGRAPHY_AVAILABLE,
    "required core cryptography dependency is not installed",
)
class CoreCryptoPolicyTests(unittest.TestCase):
    def test_default_policy_and_algorithm_confusion_fail_closed(self):
        policy = CryptoPolicy()
        policy.require_signature_algorithm("RS256")
        for algorithm in ("ML-DSA-44", "none", "HS256"):
            with self.assertRaises(CryptoPolicyError):
                policy.require_signature_algorithm(algorithm)
        self.assertIsInstance(CryptoCapabilities.detect().mldsa, bool)
        with self.assertRaises(CryptoPolicyError):
            CryptoPolicy(signature_algorithms=("ML-DSA-44",))

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        message = b"token"
        signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        verifier = RS256SignatureVerifier(policy)
        public_key = key.public_key()
        verifier.verify("RS256", public_key, signature, message)
        with self.assertRaises(CryptoPolicyError):
            verifier.verify("ML-DSA-44", public_key, signature, message)
        with self.assertRaises(InvalidSignature):
            verifier.verify("RS256", public_key, signature, b"tampered")


@unittest.skipUnless(
    COBBLESTONE_AVAILABLE,
    "optional Cobblestone adapter is not available",
)
class CobblestoneEvidenceCryptoTests(unittest.TestCase):
    def test_cobblestone_is_opt_in_and_detects_tampering(self):
        disabled_policy = CryptoPolicy()
        with self.assertRaises(CryptoPolicyError):
            CobblestoneEvidenceCrypto(
                disabled_policy,
                algorithm="COBBLESTONE-128",
                key=b"k" * 16,
                key_id="kv/key/1",
                context=b"evidence-v1",
            )
        policy = CryptoPolicy(
            evidence_encryption_algorithms=("COBBLESTONE-128",)
        )
        with self.assertRaises(CryptoPolicyError):
            CobblestoneEvidenceCrypto(
                policy,
                algorithm="COBBLESTONE-128",
                key=None,
                key_id="kv/key/1",
                context=b"evidence-v1",
            )
        crypto = CobblestoneEvidenceCrypto(
            policy,
            algorithm="COBBLESTONE-128",
            key=b"k" * 16,
            key_id="kv/key/1",
            context=b"evidence-v1",
        )
        ciphertext = crypto.encrypt(b"governance evidence")
        self.assertEqual(crypto.decrypt(ciphertext), b"governance evidence")
        with self.assertRaises(InvalidTag):
            crypto.decrypt(ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))


@unittest.skipUnless(
    X509_VERIFICATION_AVAILABLE,
    "optional X.509 verification adapter is not available",
)
class X509VerificationAdapterTests(unittest.TestCase):
    def test_x509_requires_policy_and_valid_trust_material(self):
        config = X509TrustConfig("connector.internal", ())
        disabled_policy = CryptoPolicy()
        with self.assertRaises(CryptoPolicyError):
            X509VerificationAdapter(disabled_policy, config)
        enabled = CryptoPolicy(certificate_verifiers=("X509-PATH",))
        with self.assertRaises(CryptoPolicyError):
            X509VerificationAdapter(enabled, config)
        invalid_trust = X509TrustConfig("connector.internal", (b"bad",))
        with self.assertRaises(CryptoPolicyError):
            X509VerificationAdapter(enabled, invalid_trust)


if __name__ == "__main__":
    unittest.main()
