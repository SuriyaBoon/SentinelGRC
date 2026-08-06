import importlib.util
import subprocess
import sys
import unittest

@unittest.skipUnless(importlib.util.find_spec("cryptography") is not None,"cryptography dependency is not installed")
class CryptoImportIsolationTests(unittest.TestCase):
    def test_oidc_core_does_not_import_disabled_optional_adapters(self):
        code=(
            "import sys; import oidc_auth; "
            "assert 'cryptography.cobblestone' not in sys.modules; "
            "assert 'cryptography.x509.verification' not in sys.modules"
        )
        result=subprocess.run([sys.executable,"-c",code],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

if __name__=="__main__": unittest.main()