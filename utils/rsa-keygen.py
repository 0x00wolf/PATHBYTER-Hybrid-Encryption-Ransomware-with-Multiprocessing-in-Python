from Crypto.PublicKey import RSA

key = RSA.generate(4096)
private_key = key.export_key()
public_key = key.publickey().export_key()

with open('private.pem', 'wb') as f:
    f.write(private_key)

with open('public.pem', 'wb') as f:
    f.write(public_key)

print("[+] Public key saved to")
