user = input("username: ")
# f-string — should be flagged
query = f"SELECT * FROM users WHERE username = {user}"
# concatenation — should be flagged
query2 = "SELECT * FROM users WHERE username = " + user
# parameterised — should NOT be flagged
query3 = "SELECT * FROM users WHERE username = ?"
