#!/bin/bash
# Prompt the user for a password
echo "Enter the password for the filesystem:"
read -s PASSWORD  # -s hides input for security

# Run the Python script to generate the passphrase
PASSPHRASE=$(python3 -c "
import random 
import string
def pad_password(password: str, length: int = 64) -> str:
    if len(password) >= length:
        return password[:length]  # Truncate if password is already longer than the specified length
    padding_length = length - len(password)
    padding = ''.join(random.choices(string.ascii_letters + string.digits, k=padding_length))
    return password + padding

password = '$PASSWORD'
print(pad_password(password))
")

if [ -z "$PASSPHRASE" ]; then
    echo "Error: Failed to generate passphrase. Exiting."
    exit 1
fi

# Display the passphrase to the user
echo "Your passphrase is: $PASSPHRASE"
echo "Keep this passphrase safe for reusing the system."

python3 filesys.py /app/data /app/str "$PASSPHRASE" > log.txt 2>&1 &
python3 -m http.server 8080 > /app/http_server.log 2>&1 &
echo "Filesystem started. Opening shell..."
exec /bin/bash