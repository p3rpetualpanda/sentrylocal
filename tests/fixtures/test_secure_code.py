# test_secure_code.py

import subprocess  # Insecure import of 'subprocess'. Consider using subprocess.run instead.
import os

def safe_function():
    return "Safe function"

result = eval("1 + 2")  # This is a safe use of eval, but let's assume it should be avoided for this test.
API_KEY = ""  # Empty API key is not considered a secret.
query = "SELECT * FROM users WHERE username = ?"  # Safe parameterized query.
os.system(f"echo {safe_function()}")  # Use of os.system() is dangerous and can lead to command injection.

# Example of safe subprocess usage
import subprocess
subprocess.run(["echo", "Hello, World!"], check=True)