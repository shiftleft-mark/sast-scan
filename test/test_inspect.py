import os
import tempfile

import pytest

import lib.inspect as inspect

#Mark insert test code
import hashlib
import os

salt = os.urandom(32) # Remember this
password = 'password123'

key = hashlib.pbkdf2_hmac(
    'sha256', # The hash digest algorithm for HMAC
    password.encode('utf-8'), # Convert the password to bytes
    salt, # Provide the salt
    100000 # It is recommended to use at least 100,000 iterations of SHA-256 
)

#End Mark test code

@pytest.fixture
def test_sarif_files():
    curr_dir = os.path.dirname(os.path.abspath(__file__))
    return [
        os.path.join(curr_dir, "data", "gosec-report.sarif"),
        os.path.join(curr_dir, "data", "staticcheck-report.sarif"),
    ]


def test_convert(test_sarif_files):
    with tempfile.NamedTemporaryFile(delete=False) as fp:
        inspect.convert_sarif("demo-app", {}, test_sarif_files, fp.name)
        data = fp.read()
        assert data
