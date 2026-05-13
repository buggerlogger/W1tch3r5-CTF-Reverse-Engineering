# W1tch3r5-CTF-Reverse-Engineering
challenge from https://cybertalents.com/challenges/malware/w1tch3r5

This challenge gives us a password-protected `.zip` file containing a Windows x64 executable protected by **Themida** (a commercial software protector). The binary reads user input and checks if it matches the correct flag using **RC4 encryption**.

The approach:
1. Extract the zip
2. Identify the file type and PE structure
3. Identify Themida protection
4. Dump process memory at runtime (after Themida unpacks the code)
5. Locate the decrypted `.text` section
6. Disassemble and analyze the flag-check algorithm
7. Extract the hardcoded ciphertext and XOR-obfuscated key
8. Decrypt using RC4 to get the flag

---

## Step 1 — Extract the ZIP

**Tool:** 7-Zip  
**Password:** `novirus`

```powershell
& "C:\Program Files\7-Zip\7z.exe" x W1tch3r5.zip -p"novirus" -o".\W1tch3r5_extracted" -y
```

**Output:**
```
Everything is Ok
Size:       1923070
```

Inside: `W1tch3r5.exe` (~1.9 MB)

---

## Step 2 — Identify the File Type

```powershell
$bytes = [System.IO.File]::ReadAllBytes(".\W1tch3r5_extracted\W1tch3r5.exe")
$magic = ($bytes[0..3] | ForEach-Object { $_.ToString("X2") }) -join ' '
Write-Host "Magic: $magic"

$peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
$machine  = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
Write-Host "Machine: 0x$($machine.ToString('X'))"
```

**Output:**
```
Magic: 4D 5A 90 00       ← MZ = Windows PE
Machine: 0x8664          ← x64 (64-bit)
```

---

## Step 3 — Analyze PE Sections

```powershell
$sizeOptHdr  = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
$secTableOff = $peOffset + 24 + $sizeOptHdr
$numSections = [BitConverter]::ToUInt16($bytes, $peOffset + 6)

for ($i = 0; $i -lt $numSections; $i++) {
    $off     = $secTableOff + $i * 40
    $name    = [System.Text.Encoding]::ASCII.GetString($bytes[$off..($off+7)]).TrimEnd("`0")
    $rawSize = [BitConverter]::ToUInt32($bytes, $off + 16)
    $rawOff  = [BitConverter]::ToUInt32($bytes, $off + 20)
    Write-Host "$name  rawOff=0x$($rawOff.ToString('X'))  rawSize=0x$($rawSize.ToString('X'))"
}
```

**Output:**
```
.imports  rawOff=0x1C00  rawSize=0x400
.rsrc     rawOff=0x2000  rawSize=0x200
.themida  rawOff=0x2200  rawSize=0x0       ← Themida section (no raw data!)
.boot     rawOff=0x2200  rawSize=0x1D35FE  ← Packed/compressed code (~1.9 MB)
```

> **Key finding:** The `.themida` section has `rawSize=0x0` — it exists only in virtual memory and is populated at runtime by the unpacker. The `.boot` section contains the compressed original code.

---

## Step 4 — Test the Binary (Dynamic Behavior)

```powershell
$exe = ".\W1tch3r5_extracted\W1tch3r5.exe"
"test" | &$exe
```

**Output:**
```
Enter the flag: Wrong Flag
```

The binary:
- Prints `Enter the flag:`
- Reads user input via `scanf`
- Prints `Wrong Flag` or `Correct Flag`

> **None of these strings appear in the static binary** — they are encrypted by Themida and decrypted at runtime.

---

## Step 5 — Process Memory Dump (After Themida Unpacks)

Since Themida decrypts the real code into memory at startup, we wait 4 seconds after launch (enough time for unpacking), then read all readable memory regions using `ReadProcessMemory`.

```python
# dump_mem.py
import ctypes, ctypes.wintypes as wintypes, subprocess, time, os

kernel32 = ctypes.windll.kernel32
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ           = 0x0010

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_ulonglong),
        ("AllocationBase",    ctypes.c_ulonglong),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId",       wintypes.WORD),
        ("RegionSize",        ctypes.c_ulonglong),
        ("State",             wintypes.DWORD),
        ("Protect",           wintypes.DWORD),
        ("Type",              wintypes.DWORD),
    ]

def dump_process(pid, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    hProc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    addr  = 0
    idx   = 0

    while True:
        mbi = MEMORY_BASIC_INFORMATION()
        ret = kernel32.VirtualQueryEx(hProc, ctypes.c_ulonglong(addr),
                                      ctypes.byref(mbi), ctypes.sizeof(mbi))
        if ret == 0:
            break

        readable = (
            mbi.State   == 0x1000 and          # MEM_COMMIT
            (mbi.Protect & 0x01) == 0 and      # not PAGE_NOACCESS
            (mbi.Protect & 0x100) == 0 and     # not PAGE_GUARD
            0 < mbi.RegionSize < 0x4000000
        )

        if readable:
            buf  = (ctypes.c_char * mbi.RegionSize)()
            read = ctypes.c_ulonglong(0)
            ok   = kernel32.ReadProcessMemory(
                hProc, ctypes.c_ulonglong(mbi.BaseAddress),
                buf, mbi.RegionSize, ctypes.byref(read))
            if ok and read.value > 0:
                fname = os.path.join(out_dir,
                    f"r{idx:04d}_{mbi.BaseAddress:016X}_{mbi.RegionSize:X}.bin")
                open(fname, "wb").write(bytes(buf)[:read.value])
                idx += 1

        next_addr = mbi.BaseAddress + mbi.RegionSize
        if next_addr <= addr:
            break
        addr = next_addr
    kernel32.CloseHandle(hProc)

# Launch binary (stdin piped so it waits for input)
exe  = r"W1tch3r5_extracted\W1tch3r5.exe"
proc = subprocess.Popen([exe], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print(f"PID={proc.pid} — waiting 4s for Themida to unpack...")
time.sleep(4)

dump_process(proc.pid, "memdump")
proc.stdin.write(b"test\n")
proc.stdin.close()
proc.wait(timeout=5)
print("Done. 194 regions dumped.")
```

**Output:**
```
PID=22952 — waiting 4s for Themida to unpack...
Done. 194 regions dumped.
```

---

## Step 6 — Find the Decrypted Binary in Memory

Search the dump for `"Enter the flag"`:

```python
# search_dump.py
import os

dump_dir = "memdump"
keywords = ["Enter the flag", "Wrong Flag", "Correct Flag"]

for fname in sorted(os.listdir(dump_dir)):
    if not fname.endswith(".bin"):
        continue
    data = open(os.path.join(dump_dir, fname), "rb").read()
    for kw in keywords:
        idx = data.find(kw.encode())
        if idx >= 0:
            ctx = "".join(chr(b) if 0x20<=b<=0x7e else "." for b in data[idx:idx+80])
            print(f"[{fname}] '{kw}' @ 0x{idx:X}")
            print(f"  Context: {ctx}")
```

**Output:**
```
[r0043_00007FF6053C3000_1000.bin] 'Enter the flag' @ 0x250
  Context: Enter the flag:.....%s..Correct Flag....Wrong Flag....

[r0043_00007FF6053C3000_1000.bin] also contains PDB path:
  C:\Users\joezid\Source\Repos\Egypt_nantional2\x64\Release\Egypt_nantional2.pdb
```

> **Key findings:**  
> - The real image is loaded at `0x7FF6053C0000`  
> - PDB name `Egypt_nantional2` → Egyptian CTF challenge  
> - The `.text` section is at `0x7FF6053C1000` → region `r0042_00007FF6053C1000_2000.bin`

---

## Step 7 — Map the Unpacked Image Sections

```python
import os

dump_dir = "memdump"
prefix   = "00007FF6053C"

for fname in sorted(f for f in os.listdir(dump_dir) if prefix in f):
    size = os.path.getsize(os.path.join(dump_dir, fname))
    print(f"{fname}  ({size:,} bytes)")
```

**Output:**
```
r0041_00007FF6053C0000_1000.bin   →  PE Header
r0042_00007FF6053C1000_2000.bin   →  .text  (CODE — 8 KB)
r0043_00007FF6053C3000_1000.bin   →  .rdata (strings)
r0044_00007FF6053C4000_1000.bin   →  .data
r0045_00007FF6053C5000_3000.bin   →  .pdata / exception tables
r0046_00007FF6053C8000_1000.bin   →  .idata (imports)
r0047_00007FF6053C9000_1000.bin   →  .rsrc
r0048_00007FF6053CA000_2EE000.bin →  .themida (decrypted runtime code, 3 MB)
```

---

## Step 8 — Disassemble the Main Function

```python
# disasm_main.py
from capstone import *
import os

dump_dir = "memdump"
text     = open(os.path.join(dump_dir, "r0042_00007FF6053C1000_2000.bin"), "rb").read()
BASE     = 0x7FF6053C1000

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = True

# Main function starts at offset 0x4D0
offset = 0x4D0
for ins in md.disasm(text[offset:], BASE + offset):
    print(f"  {ins.address:016X}:  {ins.mnemonic:<10} {ins.op_str}")
```

**Key instructions from disassembly:**

```asm
; === Zero a 40-byte buffer (user input) ===
7FF6053C14EB:  lea  rax, [rsp+0x68]   ; input buffer address
7FF6053C14F0:  mov  rdi, rax
7FF6053C14F5:  mov  ecx, 0x28         ; 40 bytes
7FF6053C14FA:  rep stosb              ; zero it (buffer size = 40!)

; === Hardcode 24-byte CIPHERTEXT at [rsp+0x40] ===
7FF6053C14FC:  mov  byte [rsp+0x40], 0x55
7FF6053C1501:  mov  byte [rsp+0x41], 0xa4
7FF6053C1506:  mov  byte [rsp+0x42], 0xe6
7FF6053C150B:  mov  byte [rsp+0x43], 0x99
7FF6053C1510:  mov  byte [rsp+0x44], 0xda
7FF6053C1515:  mov  byte [rsp+0x45], 0xa6
7FF6053C151A:  mov  byte [rsp+0x46], 0x6e
7FF6053C151F:  mov  byte [rsp+0x47], 0x31
7FF6053C1524:  mov  byte [rsp+0x48], 0x92
7FF6053C1529:  mov  byte [rsp+0x49], 0x6c
7FF6053C152E:  mov  byte [rsp+0x4a], 0xc0
7FF6053C1533:  mov  byte [rsp+0x4b], 0x99
7FF6053C1538:  mov  byte [rsp+0x4c], 0x08
7FF6053C153D:  mov  byte [rsp+0x4d], 0xde
7FF6053C1542:  mov  byte [rsp+0x4e], 0xaa
7FF6053C1547:  mov  byte [rsp+0x4f], 0xde
7FF6053C154C:  mov  byte [rsp+0x50], 0x5d
7FF6053C1551:  mov  byte [rsp+0x51], 0x74
7FF6053C1556:  mov  byte [rsp+0x52], 0x22
7FF6053C155B:  mov  byte [rsp+0x53], 0xe3
7FF6053C1560:  mov  byte [rsp+0x54], 0x16
7FF6053C1565:  mov  byte [rsp+0x55], 0x18
7FF6053C156A:  mov  byte [rsp+0x56], 0xfd
7FF6053C156F:  mov  byte [rsp+0x57], 0x73

; === Print "Enter the flag:" and scanf ===
7FF6053C1574:  lea  rcx, [rip+0x1cd5]
7FF6053C157B:  call printf
7FF6053C1580:  lea  rdx, [rsp+0x68]   ; destination = user input buffer
7FF6053C1585:  lea  rcx, [rip+0x1cd8] ; format = "%s"
7FF6053C158C:  call scanf

; === XOR-obfuscated RC4 KEY at [rsp+0x28] ===
; (filled AFTER scanf so it can't be patched easily)
7FF6053C1591:  mov  byte [rsp+0x28], 0xd0
7FF6053C1596:  mov  byte [rsp+0x29], 0xa1
7FF6053C159B:  mov  byte [rsp+0x2a], 0xa0
7FF6053C15A0:  mov  byte [rsp+0x2b], 0xec
7FF6053C15A5:  mov  byte [rsp+0x2c], 0xca
7FF6053C15AA:  mov  byte [rsp+0x2d], 0xf4
7FF6053C15AF:  mov  byte [rsp+0x2e], 0xe6
7FF6053C15B4:  mov  byte [rsp+0x2f], 0xca
7FF6053C15B9:  mov  byte [rsp+0x30], 0xa4
7FF6053C15BE:  mov  byte [rsp+0x31], 0xa7
7FF6053C15C3:  mov  byte [rsp+0x32], 0xa6
7FF6053C15C8:  mov  byte [rsp+0x33], 0xa1
7FF6053C15CD:  mov  byte [rsp+0x34], 0x00  ; null terminator

; === XOR loop: decode the key with 0x95 ===
; for i in range(12): [rsp+0x58+i] = [rsp+0x28+i] XOR 0x95
7FF6053C15FE:  movsxd rax, [rsp+0x20]          ; i
7FF6053C1603:  movzx  eax, byte [rsp+rax+0x28] ; enc_key[i]
7FF6053C1608:  xor    eax, 0x95                 ; decode
7FF6053C160D:  movsxd rcx, [rsp+0x20]
7FF6053C1612:  mov    byte [rsp+rcx+0x58], al   ; key[i] = result

; === malloc(96) for RC4 S-box ===
7FF6053C1618:  mov  ecx, 0x60    ; 96 bytes
7FF6053C161D:  call malloc
7FF6053C1623:  mov  [rsp+0x38], rax

; === Call RC4 encrypt function ===
7FF6053C1628:  mov  r8,  [rsp+0x38]  ; S-box buffer (malloc result)
7FF6053C162D:  lea  rdx, [rsp+0x68]  ; param2 = user input
7FF6053C1632:  lea  rcx, [rsp+0x58]  ; param1 = decoded RC4 key
7FF6053C1637:  call rc4_encrypt

; === Compare result with hardcoded ciphertext (24 bytes) ===
7FF6053C163C:  mov  r8d, 0x18        ; 24 bytes
7FF6053C1642:  lea  rdx, [rsp+0x40]  ; expected ciphertext
7FF6053C1647:  mov  rcx, [rsp+0x38]  ; RC4 output
7FF6053C164C:  call memcmp

; === Print Correct/Wrong ===
7FF6053C1651:  test eax, eax
7FF6053C1653:  jne  print_wrong
7FF6053C1655:  lea  rcx, "Correct Flag\n"
7FF6053C165C:  call printf
7FF6053C1663:  lea  rcx, "Wrong Flag\n"
7FF6053C166A:  call printf
```

---

## Step 9 — Understanding the Algorithm

From the disassembly, the flag-check works like this:

```
1. Zero 40-byte buffer
2. Store 24-byte ciphertext at [rsp+0x40]
3. Read user input with scanf into buffer [rsp+0x68]
4. Store XOR-obfuscated key bytes at [rsp+0x28]
5. Decode key: for i in 0..11: key[i] = encrypted_key[i] XOR 0x95
6. RC4_encrypt(key=decoded_key, plaintext=user_input) → output
7. memcmp(output, ciphertext, 24) == 0 → "Correct Flag"
```

Since RC4 is **symmetric**: `RC4(key, encrypt(key, plaintext)) == plaintext`  
We can reverse it: **`flag = RC4_decrypt(key, ciphertext)`**

---

## Step 10 — Decode the RC4 Key

```python
# step_key_decode.py

# XOR-obfuscated bytes (from disassembly at [rsp+0x28])
enc_key = [0xd0, 0xa1, 0xa0, 0xec, 0xca, 0xf4,
           0xe6, 0xca, 0xa4, 0xa7, 0xa6, 0xa1]

# XOR each byte with 0x95 to get the real key
key = bytes([b ^ 0x95 for b in enc_key])
print(f"RC4 Key: {key}")   # b'E45y_as_1234'
```

**Output:**
```
RC4 Key: b'E45y_as_1234'
```

XOR table:
| Encrypted | XOR 0x95 | Result |
|-----------|----------|--------|
| 0xD0 | ^ 0x95 | 0x45 = `'E'` |
| 0xA1 | ^ 0x95 | 0x34 = `'4'` |
| 0xA0 | ^ 0x95 | 0x35 = `'5'` |
| 0xEC | ^ 0x95 | 0x79 = `'y'` |
| 0xCA | ^ 0x95 | 0x5F = `'_'` |
| 0xF4 | ^ 0x95 | 0x61 = `'a'` |
| 0xE6 | ^ 0x95 | 0x73 = `'s'` |
| 0xCA | ^ 0x95 | 0x5F = `'_'` |
| 0xA4 | ^ 0x95 | 0x31 = `'1'` |
| 0xA7 | ^ 0x95 | 0x32 = `'2'` |
| 0xA6 | ^ 0x95 | 0x33 = `'3'` |
| 0xA1 | ^ 0x95 | 0x34 = `'4'` |

> **RC4 Key = `E45y_as_1234`** (a leet-speak variation of "Easy as 1234")

---

## Step 11 — Extract the Ciphertext

From the disassembly (bytes set at `[rsp+0x40]`):

```python
# step_ciphertext.py
ct = bytes([
    0x55, 0xa4, 0xe6, 0x99, 0xda, 0xa6, 0x6e, 0x31,
    0x92, 0x6c, 0xc0, 0x99, 0x08, 0xde, 0xaa, 0xde,
    0x5d, 0x74, 0x22, 0xe3, 0x16, 0x18, 0xfd, 0x73
])
print(f"Ciphertext (24 bytes): {ct.hex()}")
```

**Output:**
```
Ciphertext (24 bytes): 55a4e699daa66e31926cc09908deaade5d7422e31618fd73
```

---

## Step 12 — Final Solver: RC4 Decrypt

```python
# solve.py — Final solver

# ── Step 1: Decode the RC4 key ────────────────────────────────
enc_key = [0xd0,0xa1,0xa0,0xec,0xca,0xf4,0xe6,0xca,0xa4,0xa7,0xa6,0xa1]
key = bytes([b ^ 0x95 for b in enc_key])
print(f"[*] RC4 key: {key}")

# ── Step 2: Extract the hardcoded ciphertext ──────────────────
ct = bytes([
    0x55,0xa4,0xe6,0x99,0xda,0xa6,0x6e,0x31,
    0x92,0x6c,0xc0,0x99,0x08,0xde,0xaa,0xde,
    0x5d,0x74,0x22,0xe3,0x16,0x18,0xfd,0x73
])
print(f"[*] Ciphertext: {ct.hex()}")

# ── Step 3: RC4 algorithm ─────────────────────────────────────
def rc4(key, data):
    # KSA — Key Scheduling Algorithm
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    # PRGA — Pseudo-Random Generation Algorithm
    i = j = 0
    out = []
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out)

# ── Step 4: Decrypt (RC4 is symmetric) ───────────────────────
flag = rc4(key, ct)
print(f"[+] FLAG: {flag.decode('ascii')}")
```

**Output:**
```
[*] RC4 key: b'E45y_as_1234'
[*] Ciphertext: 55a4e699daa66e31926cc09908deaade5d7422e31618fd73
[+] FLAG: flag{Wh0_W3_W4nt_t0_b3?}
```

---

## Summary

| Step | What We Did | Tool |
|------|------------|------|
| 1 | Extract password-protected zip | 7-Zip |
| 2 | Identify file type (x64 PE EXE) | PowerShell hex check |
| 3 | Analyze PE sections | PowerShell |
| 4 | Detect **Themida** packer (`.themida` + `.boot`) | PE section names |
| 5 | Dump process memory after unpacking | Python + WinAPI |
| 6 | Find decrypted strings in dump | Python string search |
| 7 | Map unpacked image sections | File listing |
| 8 | Disassemble `.text` with Capstone | Python + Capstone |
| 9 | Identify **RC4** cipher | Manual analysis |
| 10 | Decode XOR-obfuscated RC4 key | Python |
| 11 | Extract 24-byte hardcoded ciphertext | Disassembly |
| 12 | RC4 decrypt → flag | Python |

**Flag:** `flag{Wh0_W3_W4nt_t0_b3?}`

---

## Files

```
W1tch3r5.zip          ← Original challenge file
W1tch3r5_extracted/
  W1tch3r5.exe        ← Themida-packed executable
memdump/
  r0042_*.bin         ← Decrypted .text section (our goldmine)
  r0043_*.bin         ← Decrypted .rdata (strings)
dump_mem.py           ← Memory dumper
solve.py              ← Final solver
```
