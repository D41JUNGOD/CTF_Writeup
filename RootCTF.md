## Welcome 50p (MISC)

```
제 1회 서울디지텍고등학교 해킹방어대회에 오신 것을 환영합니다.

모든 문제의 정답은 다음과 같은 형식을 가지고 있습니다.

정답 형식 = FLAG{내용} 

FLAG : FLAG{Welcome_to_Seoul_Digitech_ROOT_CTF}
```

## Calculate 167p (MISC)

```
누가 내 패스워드좀 알려줘!
hint : 역연산
```

```
def one(num, size):
    r = num + size
    r += 915
    return r


def two(num, size):
    r = num - size
    r -= 372
    return r


def three(num, size):
    r = num ^ size
    r ^= 826
    return r


def four(num, size):
    size %= 32
    r = num >> (32 - size)
    b = (num << size) - (r << 32)
    return b + r


if __name__ == "__main__":
    result = [5040, 4944, 5088, 4992, 7232, 4848, 7584, 7344, 4288, 7408, 7360, 7584, 4608, 4880, 4320, 7328, 7360,
              4608, 4896, 4320, 7472, 7328, 7360, 4608, 4752, 4368, 4848, 4608, 4848, 4368, 4944, 7200]
    string = raw_input("Input String : ")
    Number = []
    tmp = 0

    for i in string:
        Number.append(ord(i))

    for i in Number:
        Number[tmp] = one(i, 100)
        tmp += 1
    tmp = 0

    for i in Number:
        Number[tmp] = two(i, 100)
        tmp += 1
    tmp = 0

    for i in Number:
        Number[tmp] = three(i, 100)
        tmp += 1
    tmp = 0

    for i in Number:
        Number[tmp] = four(i, 100)
        tmp += 1

    print Number
    if Number == result:
        print "Correct!!"
    else:
        print "Incorrect.."
```
 이런식으로 마지막 부분에 비교하는 구문을 빼버리고 바뀐 결과 값을 출력해주게 바꾼다.

```
def one(num, size):
    r = num + size
    r += 915
    return r


def two(num, size):
    r = num - size
    r -= 372
    return r


def three(num, size):
    r = num ^ size
    r ^= 826
    return r


def four(num, size):
    size %= 32
    r = num >> (32 - size)
    b = (num << size) - (r << 32)
    return b + r


if __name__ == "__main__":
    result = [5040, 4944, 5088, 4992, 7232, 4848, 7584, 7344, 4288, 7408, 7360, 7584, 4608, 4880, 4320, 7328, 7360,
              4608, 4896, 4320, 7472, 7328, 7360, 4608, 4752, 4368, 4848, 4608, 4848, 4368, 4944, 7200]
    string = input("Input String : ")
    Number = []
    tmp = 0

    for i in string:
        Number.append(ord(i))

    for i in Number:
        Number[tmp] = one(i, 100)
        tmp += 1
    tmp = 0

    for i in Number:
        Number[tmp] = two(i, 100)
        tmp += 1
    tmp = 0

    for i in Number:
        Number[tmp] = three(i, 100)
        tmp += 1
    tmp = 0

    for i in Number:
        Number[tmp] = four(i, 100)
        tmp += 1

    print (Number)
```

그리고 이제 하나하나 문자들을 쳐 보면서 문자마다 나오는 값을 하나하나 기록해두고 

result 에 들어있는 값과 비교하며 알맞는 글자를 찾으면 된다.

FLAG : FLAG{Rev3rse_P1us_M1nus_X0R_R0L} 

## Do you know ㅁㅁㅁ? 706p (MISC)

```
어렵디 어려운 이 문제... 누가 풀 것인가?

복호화 사이트 -> ㅁㅁㅁencryption.com

hint1 : cat == 고양이

hint2 : md5encryption.com

hint3 : dog == 갯수
```

```
Find the Flag!
[0 = 4dog] [2 = 1dog] [4 = 4dog] [5 = 4dog]
[6 = 1dog] [7 = 1dog] [8 = 2dog] [9 = 3dog]
[a = 4dog] [b = 3dog] [c = 3dog] [d = 2dog]


g d a 6 v z 1 3
d o 9 8 j 0 1 x
1 b i 9 8 1 2 6
b z 9 6 y u 3 1

k 6 9 7 j i h z
k y i j t b i n
y 9 5 g f j 7 b
3 n i u t g h m

a b c d e f g h
1 d 7 9 7 9 6 6
c b a w c g 9 9
c c a a c c d d

f 1 5 1 2 g 4 1
h 6 4 c b 1 0 8
a h 9 8 m f i 2
i 4 j n g i 9 4

...
```

힌트가 ‘cat = 고양이’ 인것으로 보아 ‘dog = 개’라고 유추할 수 있다.
잘 생각해봐도 뭔지 모르겠었는데 3번째 힌트인 dog == 갯수라는 것을 보고 문화충격을 받았다. 
바로 0은 4개 2는 1개 이런식의 조건을 모두 만족하는 문자열을 찾고 md5을 돌리면 flag가 나온다.

FLAG : FLAG{MD5_3nCryPt_Ye@h!}

## Vocabulary 460p (MISC)

```
플래그가 적힌 친구의 단어장을 잃어버렸다 
어서 빨리 찾아야 된다.
그 친구가 화내기 전에 플래그라도 찾아보자
hint : PNG height
```

```
COpyiNg iS AlSO rEcOMMENDED. It MAy bE ..SupErStitiON, but it iS truE.IN ADDitiON, thE FLAG MAy ..bE........bEE.......bEEEE.....{ tHANk_FiND_MY_vOCAbuLAry..}. MAybE NOt. Or iNcrEASE the hEight tO 1000px.
```

HxD 로 열어보면 끝 쪽에 사진의 높이를 1000px로 변경해달라는 말이 있다. 

이 파일은 확장자가 PNG이다. PNG는 기본적으로 파일헤더에 넓이와 높이를 설정할 수 있게 들어 있다. 변경해주면 된다.

![ex_screenshot](https://github.com/D41JUNGOD/CTF/blob/master/jpg/pleas_find.png)

FLAG : FLAG{_1vErticAl_2rEADiNg_3TAStlSb} 

## Stage Game 229p (Reversing)

```
인내의 시간..
Stage Level 1~10
hint : Sleep
```

OllyDbg로 까보면 Stage를 구별할 수 있는 부분이 있습니다.

![ex_screenshot](https://github.com/D41JUNGOD/CTF/blob/master/jpg/pleas_find.PNG)

그리고 그 안을 스텝 인투로 들어가보면 결정적인 Sleep 함수가 있는 부분을 찾을 수 있다.

![ex_screenshot](https://github.com/D41JUNGOD/CTF/blob/master/jpg/olly2.PNG)

여기서 eax값을 0으로 바꾸어 주면 Sleep함수를 건너뛸 수 있다.

이렇게 10stage까지가면 flag를 얻을 수 있다.

FLAG : FLAG{Y0ur_p4t1enc3_1s_gr3at!} 

## LOGIN 50p (Web)

```
로그인 페이지인데 로그인이 안된다... 
로그인을 성공하고 짱해커가 되어보자!!
Hint : Array, length<6
Hint2 : Get으로 배열을 전송하는 방법, sql injection
```

링크를 타고 들어가보면 그냥 flag가 있다. base64로 5번 디코딩해주면 된다.

FLAG : FLAG{jjang_easy} 

## 보물찾기 149p (Web)

```
홈페이지 내에 존재하는 플레그를 찾아보세염!
```

그냥 홈페이지에 존재하는 플래그를 찾으면 된다.
http://sdhsroot.kro.kr/vendor/bootstrap/css/bootstrap.min.css
플래그는 얄밉게 부트스트랩에 들어있었다.

FLAG : FLAG{bootstrap_1s_jj4ng}





