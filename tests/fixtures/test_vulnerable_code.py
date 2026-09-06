import os

# Unsafe use of eval
eval("print('Hello, World!')")

# Hard-coded secret
API_KEY = "1234567890"

# Unsafe database query
query = "SELECT * FROM users WHERE username = 'admin'"

# Use of os.system
os.system("echo Hello, World!")
