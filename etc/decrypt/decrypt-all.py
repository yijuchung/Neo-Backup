#!python

'''
Quickly implemented AES-GCM-NoPadding decryption tool that can decrypt Neo Backup encrypted files.
Feel free to use, study and extend it.

Backup format (per encrypted ".enc" file):

    [ 12-byte GCM nonce ][ ciphertext ][ GCM tag ]

The key-derivation parameters are read from the backup's ".properties" metadata file, so each
backup is self-describing (no hard-coded salt or iteration count):

    kdfSalt        random per-backup salt (JSON array of signed bytes)
    kdfIterations  PBKDF2 iteration count
    kdfAlgorithm   PBKDF2 algorithm, e.g. "PBKDF2WithHmacSHA256"
    keyLength      derived-key length in bits (e.g. 256)
    gcmTagBits     GCM authentication tag length in bits (e.g. 128)
'''
import sys
import os
import shutil
import json
from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac

# don't change

EXT = ".enc"
GCM_NONCE_LEN = 12          # bytes, prepended to every .enc file

# map a Java PBKDF2 algorithm name to a hashlib hash name
def hash_name_for(algorithm):
    a = (algorithm or "").upper()
    if "SHA512" in a:
        return 'sha512'
    if "SHA256" in a:
        return 'sha256'
    if "SHA1" in a:
        return 'sha1'
    return 'sha256'

def bytes_from_signed_list(values):
    return b''.join(map(lambda i: int(i).to_bytes(1, 'big', signed=True), values))

def decrypt(backup, password, files):

    try:
        with open(backup + '.properties', 'r') as f:

            try:

                properties = json.load(f)

                encryption = properties.pop('cipherType', 'none')

                if encryption == "AES/GCM/NoPadding":

                    salt_values = properties.get('kdfSalt')
                    if not salt_values:
                        print("ERROR: missing kdfSalt in properties - cannot decrypt "
                              "(backups from before per-backup salt are not supported)")
                        return

                    salt = bytes_from_signed_list(salt_values)
                    iterations = int(properties.get('kdfIterations'))
                    key_len = int(properties.get('keyLength', 256)) // 8
                    tag_len = int(properties.get('gcmTagBits', 128)) // 8
                    hash_name = hash_name_for(properties.get('kdfAlgorithm'))

                    # derive the key once per backup (same salt + iterations for every file)
                    key = pbkdf2_hmac(hash_name=hash_name,
                                      password=password,
                                      salt=salt,
                                      iterations=iterations,
                                      dklen=key_len)

                    decrypted_backup = backup + "-DECRYPTED"

                    for file in sorted(files):

                        path = os.path.join(backup, file)

                        if file.endswith(EXT):

                            encrypted_path = path

                            with open(encrypted_path, 'rb') as input_file:

                                print("decrypt", encrypted_path)

                                os.makedirs(decrypted_backup, exist_ok=True)

                                encrypted_content = input_file.read()

                                # per-file layout: nonce, ciphertext, tag
                                nonce = encrypted_content[:GCM_NONCE_LEN]
                                ciphertext = encrypted_content[GCM_NONCE_LEN:-tag_len]
                                tag = encrypted_content[-tag_len:]

                                cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                                decrypted_content = cipher.decrypt_and_verify(ciphertext, tag)

                                basename = os.path.splitext(file)[0]
                                decrypted_path = os.path.join(decrypted_backup, basename)

                                with open(decrypted_path, 'wb') as output_file:
                                    output_file.write(decrypted_content)

                        else:

                            print("copy   ", path)

                            os.makedirs(decrypted_backup, exist_ok=True)
                            shutil.copy(path, decrypted_backup)

                    with open(decrypted_backup + '.properties', 'w') as f:

                        properties.pop('cipherType', '')        # already done, just to be sure
                        json.dump(obj=properties, fp=f, indent=4)

                else:
                    print("unknown cipherType:", encryption)

            except Exception as e:
                print("ERROR:", e)

    except:
        pass # no properties file

    print()

#print(sys.argv)

try:
    password  = sys.argv[1].encode('utf-8')
    directory = sys.argv[2]
except:
    print("usage: ", sys.argv[0], "PASSWORD", "BACKUPDIRECTORY")
    exit(1)

print("password: ", password.decode('utf-8'))
print("directory:", directory)

for folder, dirs, files in os.walk(directory):
    for file in files:
        if file.endswith(EXT):
            print(folder, "\t", files)
            decrypt(folder, password, files)
