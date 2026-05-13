
# Decode RC4 key (XOR 0x95 with hardcoded bytes from [rsp+0x28])
enc_key = [0xd0,0xa1,0xa0,0xec,0xca,0xf4,0xe6,0xca,0xa4,0xa7,0xa6,0xa1]
key = bytes([b ^ 0x95 for b in enc_key])
print("RC4 key:", key)

# Ciphertext from [rsp+0x40] (24 bytes hardcoded in main)
ct = bytes([0x55,0xa4,0xe6,0x99,0xda,0xa6,0x6e,0x31,0x92,0x6c,0xc0,0x99,
            0x08,0xde,0xaa,0xde,0x5d,0x74,0x22,0xe3,0x16,0x18,0xfd,0x73])
print("Ciphertext:", ct.hex())

def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

flag = rc4(key, ct)
print("Decrypted:", flag)
try:
    print("Flag:", flag.decode("ascii"))
except Exception as e:
    print("Decode error:", e)
    print("Hex:", flag.hex())

# Verify by running binary
import subprocess
result = subprocess.run(
    [r"c:\Users\ASOO\Desktop\REDDIT\web reverse\DGO\W1tch3r5_extracted\W1tch3r5.exe"],
    input=flag,
    capture_output=True,
    timeout=5
)
print("Binary output:", result.stdout + result.stderr)
