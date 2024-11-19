#!/bin/bash
read -p "Enter a passphrase for existing filesystem or press Enter to generate a new filesystem: " USER_PASSPHRASE

if [ -z "$USER_PASSPHRASE" ]; then
    # Generate a passphrase if the user didn't input one
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

    echo "Your passphrase is: $PASSPHRASE"
    echo "Keep this passphrase safe for reusing the system."

else
    # Use the passphrase provided by the user
    PASSPHRASE="$USER_PASSPHRASE"
    echo "Using user-provided passphrase: $PASSPHRASE"
fi

python3 filesys.py /app/data /app/str "$PASSPHRASE" > log.txt 2>&1 &
sleep 3
cd str/
python3 -m http.server 8080 > /app/http_server.log 2>&1 &
echo "Filesystem started. Opening shell..."
cd ../data
exec /bin/bash