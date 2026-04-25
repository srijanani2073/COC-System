import bcrypt
password = b"view123"

hashed = bcrypt.hashpw(password, bcrypt.gensalt())
print(hashed)