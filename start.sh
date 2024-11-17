#!/bin/bash

# Run the Python script to generate the passphrase
PASSPHRASE=$(python3 -c "
import secrets
from quantcrypt.kdf import Argon2
import binascii  

secret_key = secrets.token_bytes(32)
argon = Argon2.Key(secret_key)

print(binascii.hexlify(argon.secret_key).decode('utf-8'))
")

if [ -z "$PASSPHRASE" ]; then
    echo "Error: Failed to generate passphrase. Exiting."
    exit 1
fi

# Display the passphrase to the user
echo "Your passphrase is: $PASSPHRASE"
echo "Keep this passphrase safe for reusing the system."

python3 filesys.py mnt str $PASSPHRASE
python3 filesys.py /app/data /app/str "$PASSPHRASE" > log.txt 2>&1 &
python3 -m http.server 8080 > /app/http_server.log 2>&1 &
echo "Filesystem started. Opening shell..."
exec /bin/bash