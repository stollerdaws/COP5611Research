import secrets
from quantcrypt.cipher import Krypton

# Krypton requires the symmetric secret key to be 64 bytes long.
secret_key = secrets.token_bytes(64)
plaintext = b"Welcome to your encrypted filesystem!"

krypton = Krypton(secret_key)

# Encrypt the plaintext and generate the verification data packet.
krypton.begin_encryption()
ciphertext = krypton.encrypt(plaintext)
verif_dp = krypton.finish_encryption()
pack = ciphertext + verif_dp
print(pack)
print(ciphertext)
print(pack[-160:])
# Decrypt the plaintext and verify its validity in finish_decryption call.
krypton.begin_decryption(pack[-160:])
plaintext_copy = krypton.decrypt(pack[:-160])
krypton.finish_decryption()
print(plaintext_copy)
assert plaintext_copy == plaintext