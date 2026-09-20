import pickle
import subprocess
import hashlib

# pickle deserialisation — should be flagged
data = pickle.loads(user_input)

# subprocess with shell=True — should be flagged
subprocess.run(cmd, shell=True)

# weak hashing — should be flagged
digest = hashlib.md5(password.encode())

# clean variants — should NOT be flagged
subprocess.run(["echo", "hello"], check=True)
digest2 = hashlib.sha256(password.encode())
