import os
import subprocess
import getpass
from Crypto.PublicKey import RSA

# install pycrypto
GROUP_MEMBERSHIP_LOOKUP = "LOCAL" # can be LDAP or LOCAL
GROUP_MEMBERSHIP_LOOKUP_IDENTIFIER = "ssh-" # used to locate different groups.

# user = os.environ.get('USER') # vulnerable
user = subprocess.check_output(["id", "-u", "-n"]).decode("utf-8").strip("\n")
home_dir = os.environ.get('HOME')
ssh_dir = home_dir + "/.ssh"
private_key = ssh_dir + "/id_rsa"
public_key = ssh_dir + "/id_rsa.pub"
signed_key = ssh_dir + "/id_rsa-cert.pub"

if not os.path.isdir(ssh_dir):
    print(f"creating '.ssh' directory for {user}...")
    os.mkdir(ssh_dir)
    os.chmod(ssh_dir, int('700', base=8)) # set dir to rwx for user only

if os.path.exists(private_key):
    print(f"deleting {private_key}...")
    os.remove(private_key)

if os.path.exists(public_key):
    print(f"deleting {public_key}")
    os.remove(public_key)

if os.path.exists(signed_key):
    print(f"deleting {signed_key}")
    os.remove(signed_key)

print(f"creating SSH keys for {user}...")

key_passphrase = ""
while True:
    pwd1 = getpass.getpass("Enter new SSH key passphrase: ")
    if pwd1 == "":
        print("\nERROR: Empty passphrases are not permitted!")
        continue
    if len(pwd1) < 5:
        print("\nERROR: Passphrase must be 5 charachters or longer!")
        continue
    if "'" in pwd1 or "\"" in pwd1:
        print("\nERROR: Passphrase can not contain a ' or a \"!")
        continue

    pwd2 = getpass.getpass("Verify passphrase: ")

    if pwd1 == pwd2:
        key_passphrase = pwd1
        break
    else:
        print("\nERROR: Passphrases did not match, try again...")

subprocess.Popen(["ssh-keygen", "-t", "rsa", "-b", "2048", "-f", f"{private_key}", "-q", "-N", f"{key_passphrase}"])

# had to use a different method
#key = RSA.generate(2048)
#with open(private_key, 'wb') as content_file:
#    os.chmod(private_key, int('600', base=8))
#    content_file.write(key.exportKey('PEM'))
#pubkey = key.publickey()
#with open(public_key, 'wb') as content_file:
#    os.chmod(public_key, int('644', base=8))
#    content_file.write(pubkey.exportKey('OpenSSH'))

# read roles from LDAP or local group membership
groups = []
if GROUP_MEMBERSHIP_LOOKUP == "LOCAL":
     tmp_groups = subprocess.check_output(["groups"]).decode("utf-8").strip("\n").split()
     for g in tmp_groups:
         if GROUP_MEMBERSHIP_LOOKUP_IDENTIFIER in g:
             groups.append(g)

print(groups)
#elif GROUP_MEMBERSHIP_LOOKUP == "LDAP":


# call vault API to sign public key
