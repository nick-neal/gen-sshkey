import os
import subprocess
import getpass
import requests
import json
import time
from Crypto.PublicKey import RSA

# install pycrypto
GROUP_MEMBERSHIP_LOOKUP = "LOCAL" # can be LDAP or LOCAL
GROUP_MEMBERSHIP_LOOKUP_IDENTIFIER = "ssh-" # used to locate different groups.
VAULT_SERVER = "vault.local:8200"
VAULT_HTTPS = False

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

# adding to give time to write public key
time.sleep(1)

public_key_contents = ""
f=open(public_key, "r")
if f.mode == "r":
    public_key_contents = f.read().strip("\n")

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
groups = ""
if GROUP_MEMBERSHIP_LOOKUP == "LOCAL":
    tmp_groups = subprocess.check_output(["groups"]).decode("utf-8").strip("\n").split()
    for g in tmp_groups:
        if GROUP_MEMBERSHIP_LOOKUP_IDENTIFIER in g:
            groups = groups + g + " "

    groups = groups.strip()


#elif GROUP_MEMBERSHIP_LOOKUP == "LDAP":

# call vault API to get client token

vault_user = getpass.getuser("Enter vault username: ")
vault_pass = getpass.getpass("Enter vault password: ")

login_endpoint = f"v1/auth/userpass/login/{vault_user}"
vault_login_url = ""
if VAULT_HTTPS:
    vault_login_url = f"https://{VAULT_SERVER}/{login_endpoint}"
else:
    vault_login_url = f"http://{VAULT_SERVER}/{login_endpoint}"

login_data = {"password": vault_pass}
data = json.dumps(login_data)

r = requests.post(url=vault_login_url, data=data)
response = json.loads(r.text)
client_token = response["auth"]["client_token"]

# call vault API to sign public key

key_name = f"{user}-key"
ca_endpoint = f"v1/ssh/sign/{key_name}"
vault_ca_url = ""
if VAULT_HTTPS:
    vault_ca_url = f"https://{VAULT_SERVER}/{ca_endpoint}"
else:
    vault_ca_url = f"http://{VAULT_SERVER}/{ca_endpoint}"

headers = {"X-Vault-Token" : "<TOKEN>"}
ca_data = {
    "public_key": public_key_contents,
    "ttl": "12h",
    "valid_principals": groups,
    "cert_type": "user",
    "key_id": user
    }

data = json.dumps(ca_data)
