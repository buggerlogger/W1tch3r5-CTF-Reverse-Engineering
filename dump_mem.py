
import ctypes
import ctypes.wintypes as wintypes
import subprocess
import time
import os
import struct

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
    if not hProc:
        print(f"[!] OpenProcess failed: {ctypes.GetLastError()}")
        return

    addr  = 0
    idx   = 0
    total = 0

    while True:
        mbi   = MEMORY_BASIC_INFORMATION()
        ret   = kernel32.VirtualQueryEx(hProc, ctypes.c_ulonglong(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if ret == 0:
            break

        MEM_COMMIT   = 0x1000
        PAGE_NOACCESS = 0x01
        PAGE_GUARD    = 0x100

        readable = (
            mbi.State   == MEM_COMMIT and
            (mbi.Protect & PAGE_NOACCESS) == 0 and
            (mbi.Protect & PAGE_GUARD)    == 0 and
            0 < mbi.RegionSize < 0x4000000
        )

        if readable:
            buf  = (ctypes.c_char * mbi.RegionSize)()
            read = ctypes.c_ulonglong(0)
            ok   = kernel32.ReadProcessMemory(hProc, ctypes.c_ulonglong(mbi.BaseAddress),
                                              buf, mbi.RegionSize, ctypes.byref(read))
            if ok and read.value > 0:
                data = bytes(buf)[:read.value]
                fname = os.path.join(out_dir, f"r{idx:04d}_{mbi.BaseAddress:016X}_{mbi.RegionSize:X}.bin")
                with open(fname, "wb") as f:
                    f.write(data)
                total += read.value
                idx   += 1

        next_addr = mbi.BaseAddress + mbi.RegionSize
        if next_addr <= addr:
            break
        addr = next_addr

    kernel32.CloseHandle(hProc)
    print(f"[+] Dumped {idx} regions, {total:,} bytes total")

def search_dump(out_dir, keywords):
    hits = {}
    for fname in sorted(os.listdir(out_dir)):
        if not fname.endswith(".bin"):
            continue
        path = os.path.join(out_dir, fname)
        with open(path, "rb") as f:
            data = f.read()
        for kw in keywords:
            kw_b = kw.encode("ascii")
            pos  = 0
            while True:
                idx = data.find(kw_b, pos)
                if idx < 0:
                    break
                ctx_start = max(0, idx - 30)
                ctx_bytes = data[ctx_start : idx + 100]
                ctx = "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in ctx_bytes)
                hit = f"  [{fname}] '{kw}' @0x{idx:X}: {ctx}"
                hits.setdefault(kw, []).append(hit)
                pos = idx + 1
    return hits

# ---- Main ----
exe     = r"c:\Users\ASOO\Desktop\REDDIT\web reverse\DGO\W1tch3r5_extracted\W1tch3r5.exe"
out_dir = r"c:\Users\ASOO\Desktop\REDDIT\web reverse\DGO\memdump"

print("[*] Starting W1tch3r5.exe with stdin pipe (so it waits for input)...")
proc = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
print(f"[*] PID={proc.pid} — sleeping 4s for Themida to unpack...")
time.sleep(4)

print("[*] Dumping process memory...")
dump_process(proc.pid, out_dir)

# Send input and let process finish
proc.stdin.write(b"test\n")
proc.stdin.close()
proc.wait(timeout=5)

# Search
keywords = ["Enter the flag", "Wrong Flag", "Correct", "flag{", "evil", "witch", "Witch", "Evil", "lesser", "Lesser", "greater", "Greater"]
print("\n[*] Searching dumped memory...")
hits = search_dump(out_dir, keywords)
for kw, matches in hits.items():
    print(f"\n=== '{kw}' ({len(matches)} hits) ===")
    for h in matches[:10]:
        print(h)
