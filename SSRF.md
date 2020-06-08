## SSRF

SSRF(服务器端请求伪造) 是一种由攻击者构造形成由服务端发起请求的一个安全漏洞。

比如一个常规的可能造成SSRF的链接：

```
www.xxx.com/img?file=http://www.xxx.com/img/1.jpg
```

可以利用来探测服务，配合其他协议来读取文件，利用主机其他应用的端口漏洞来执行命令等。

python中可以造这种问题的常用请求库：

```
pycurl
urllib
urllib3
requests
```

### pycurl

一个libcurl的python接口，功能挺多，就是使用比较繁杂，python3下做一个GET请求

```python
>>> import pycurl
>>> from io import BytesIO
>>> curl = pycurl.Curl()
>>> curl.setopt(curl.URL, 'http://pycurl.io')
>>> buffer = BytesIO()
>>> curl.setopt(curl.WRITEDATA, buffer)
>>> curl.perform()
>>> curl.close()
>>> body = buffer.getvalue()
>>> print(body.decode('iso-8859-1'))
```

如果需要设置参数，部分常用参数

```python
curl.setopt(curl.FOLLOWLOCATION, True)   #自动进行跳转抓取，默认不跳转
curl.setopt(curl.MAXREDIRS,5)            #设置最多跳转多少次
curl.setopt(curl.CONNECTTIMEOUT, 60)     #设置链接超时
curl.setopt(curl.USERAGENT,ua)           #传入ua
curl.setopt(curl.HTTPHEADER,self.headers)     #传入请求头
```

其他设置查看官方的文档：http://pycurl.io/docs/latest/quickstart.html

我们用这个库在flask中模拟一个SSRF的形成：

```python
def SSRF():
    if request.values.get('file'):
        file = request.values.get('file')
        curl = pycurl.Curl()
        curl.setopt(curl.URL, file)
        curl.setopt(curl.FOLLOWLOCATION, True)
        curl.setopt(curl.MAXREDIRS, 3)
        curl.setopt(curl.CONNECTTIMEOUT, 5)
        buf = BytesIO()
        curl.setopt(curl.WRITEDATA, buf)
        curl.perform()
        curl.close()
        body = buf.getvalue()
        return render_template('ssrf.html', file = body.decode('utf-8'))
    else:
        return Response('<p>请输入file地址</p>')
```

在模板中填写`{{ file|safe }}`来正常解析HTML节点。当正常请求的时候可以看到显示的页面

```
http://127.0.0.1:5000/ssrf?file=http://www.baidu.com
http://127.0.0.1:5000/ssrf?file=file://C:/Windows/win.ini
```

### urllib

python3的标准请求库，导入`urllib.request`即可。自动处理跳转

```python
>>> import urllib.request
>>> req = urllib.request.urlopen("http://www.baidu.com")
>>> print(req.read())
```

同样来模拟一个ssrf的产生

```python
@app.route('/ssrf')
def SSRF():
    if request.values.get('file'):
        file = request.values.get('file')
        req = urllib.request.urlopen(file)
        body = req.read().decode('utf-8')
        return render_template('ssrf.html', file=body)
    else:
        return Response('<p>请输入file地址</p>')
```

只不过此处使用来读取文件的时候会有问题

```
http://127.0.0.1:5000/ssrf?file=http://www.baidu.com
http://127.0.0.1:5000/ssrf?file=file://C:/Windows/win.ini
#file not on local host
```

跟步调试看一下原因：

```python
@full_url.setter
def full_url(self, url):
    # unwrap('<URL:type://host/path>') --> 'type://host/path'
    self._full_url = unwrap(url)
    self._full_url, self.fragment = splittag(self._full_url)
    self._parse()
```

跳转到unwrap，处理后还是返回`file://C:/Windows/win.ini`，因此上面的`self._full_url`仍然是原参数

```python
def unwrap(url):
    """unwrap('<URL:type://host/path>') --> 'type://host/path'."""
    url = str(url).strip()
    if url[:1] == '<' and url[-1:] == '>':
        url = url[1:-1].strip()
    if url[:4] == 'URL:': url = url[4:].strip()
    return url        #file://C:/Windows/win.ini
```

再此跳转到如下一个正则处理中，这时候处理出来的scheme为`file`，data为`//C:/Windows/win.ini`

```python
_typeprog = None
def splittype(url):
    """splittype('type:opaquestring') --> 'type', 'opaquestring'."""
    global _typeprog
    if _typeprog is None:
        _typeprog = re.compile('([^/:]+):(.*)', re.DOTALL)

    match = _typeprog.match(url)
    if match:
        scheme, data = match.groups()
        return scheme.lower(), data
    return None, url
```

返回到如下处进入splithost，同样分割域名和路径。但是这时候会把`C:`分析为域名和端口，后面为路径。

```python
def _parse(self):
    self.type, rest = splittype(self._full_url)
    if self.type is None:
    	raise ValueError("unknown url type: %r" % self.full_url)
    self.host, self.selector = splithost(rest)
    if self.host:
    	self.host = unquote(self.host)
```

这时候的`self.host`就是`C:`。后面再经过一段处理就会看到下面的地址分析。

`SplitResult(scheme='file', netloc='C:', path='/Windows/win.ini', query='', fragment='')`

再回到`ParseResult`

```python
def urlparse(url, scheme='', allow_fragments=True):
    """Parse a URL into 6 components:
    <scheme>://<netloc>/<path>;<params>?<query>#<fragment>
    Return a 6-tuple: (scheme, netloc, path, params, query, fragment).
    Note that we don't break the components up in smaller bits
    (e.g. netloc is a single string) and we don't expand % escapes."""
    url, scheme, _coerce_result = _coerce_args(url, scheme)
    splitresult = urlsplit(url, scheme, allow_fragments)
    scheme, netloc, url, query, fragment = splitresult
    if scheme in uses_params and ';' in url:
        url, params = _splitparams(url)
    else:
        params = ''
    result = ParseResult(scheme, netloc, url, params, query, fragment)
    return _coerce_result(result)
```

再走一段有的没的，就可以看到这一段代码

```python
class FileHandler(BaseHandler):
    # Use local file or FTP depending on form of URL
    def file_open(self, req):
        url = req.selector
        if url[:2] == '//' and url[2:3] != '/' and (req.host and
                req.host != 'localhost'):
            if not req.host in self.get_names():
                raise URLError("file:// scheme is supported only on localhost")
        else:
            return self.open_local_file(req)
```

再到`open_local_file`查找本地文件，参数`localfile`就是`\\windows\\win.ini`。只不过后面会用`socket.gethostbyname(host)`来获取主机名，`host`就是`C`。于是很愉快的报错了，就会显示`file not on local host`的错误提示。

也就是问题出现再上面`splithost`正则解析的时候问题，不应该把`C:`解析成主机和端口，导致来做请求和分析文件路径的时候出现了偏差。只要多加个斜杠把主机位置置为空。总感觉是我使用错误导致踩坑？？？

```
http://127.0.0.1:5000/ssrf?file=file:///C:/Windows/win.ini
```

### requests

requests库算是最常用的第三方HTTP库，用以下代码模拟

```python
@app.route('/ssrf')
def SSRF():
    if request.values.get('file'):
        file = request.values.get('file')
        req = requests.get(file)
        return render_template('ssrf.html', file=req.content.decode('utf-8'))
    else:
        return Response('<p>请输入file地址</p>')
```

不过requests也有一个Adapter的字典，请求类型为http://，或者https://。所以也算是有一部分限制。

```
self.mount('https://', HTTPAdapter())
self.mount('http://', HTTPAdapter())
```

要是需要利用来读取文件，可以配合`requests_file`来增加对file协议的支持。

```python
from requests_file import FileAdapter

s = requests.Session()
s.mount('file://', FileAdapter())
req = s.get(file)
```

上面的显示多多少少的看起来有点多此一举，都是请求到数据在去显示。

关于SSRF利用：https://_thorns.gitbooks.io/sec/content/ssrf_tips.html

构造一个302跳转，请求即可显示百度页面。

```python
@app.route('/location')
def location():
    return render_template('xss.html'), 302, [('Location','http://www.baidu.com')]
```

### 修复代码

如果要处理SSRF，需要认识到的一点就是，如何识别它的请求地址，通常所说的就是，不准请求内网地址.

一种利用手法是正则匹配，但是这种是有很多办法绕过的，当然如果你是白名单正则限制，那就不一定了。比如限制在`100.100.100.x`这个C段内。

```python
host = urllib.parse.urlparse(file)
pattern = re.compile('^100\.100\.100\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[0-9])$')
if pattern.search(host.netloc):
	req = urllib.request.urlopen(file)
	body = req.read().decode('utf-8')
else:
	return Response('不允许的IP地址')
```

python3中有一个模块为`ipaddress`，其中有一个方法是判断是否为内网IP的办法。如果采用进制的形式绕过的话，就会报一个异常。

```python
	file = urllib.parse.urlparse(file).hostname
        try:
            if not ipaddress.ip_address(file).is_private:
                req = urllib.request.urlopen(file)
                body = req.read().decode('utf-8')
                return render_template('ssrf.html', file=body)
            else:
                return Response('不允许的IP地址')
        except:
            return Response('IP不合法')
```

但是这样任然有一个问题就是，实际中绝大多数是采用域名而非IP的形式，即使采用了IP也不一定保证就可以在一定的可限制范围内。也许我们可以采用socket来获取域名的IP来判断，但是这样还是有一个问题就是302跳转。对于一些资源的展示，一般不需要跳转，禁止跳转也可以达到一部分安全的限制。

至此，需要一个可以解析域名，同时可以准确判断IP的归属，并且不被302所限制的判断。就需要对每一次的跳转进行判断。同样用urllib库来做实验。如下，先解决IP的归属判断：

```python
file = urllib.parse.urlparse(file).hostname
name = socket.gethostbyname(file)   #只支持IPv4
try:
	if not ipaddress.ip_address(name).is_private:
        req = urllib.request.urlopen(file)
        body = req.read().decode('utf-8')
        return render_template('ssrf.html', file=body)
	else:
		return Response('不允许的IP地址')
except:
	return Response('IP不合法')
```

然后再解决跳转的问题，由于urllib是默认跳转的，所以我们需要修改来控制跳转。通过控制`redirect_request`来判断跳转的url是不是内网地址，是内网地址返回403。

```python
class Redict(urllib.request.HTTPRedirectHandler):
    def newurls(self, url):
        file = urllib.parse.urlparse(url).hostname
        name = socket.gethostbyname(file)
        try:
            if ipaddress.ip_address(name).is_private:
                return True     #私有
            else:
                return False    #公有
        except:
            return True

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.newurls(newurl):
            return urllib.request.Request(newurl)
        else:
            return abort(403)

@app.route('/ssrf2')
def location2():
    if request.values.get('file'):
        file = request.values.get('file')
        try:
            opener = urllib.request.build_opener(Redict)
            response = opener.open(file)
        except:
            return Response('地址不合法')
        body = response.read().decode('utf-8')
        return render_template('ssrf.html', file=body)
    else:
        return Response('<p>请输入file地址</p>')
```

还有一个问题就是IP的进制转换问题，不过有意思的是IP的进制转换在以上模块中并不会正常引用，比如urllib，最后进行通信的时候是调用`socket.getaddrinfo()`来解析域名，非标准IP格式，会报异常。

```
>>> socket.getaddrinfo('0x7F.0.0.1', 5000)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "D:\anaconda3\lib\socket.py", line 748, in getaddrinfo
    for res in _socket.getaddrinfo(host, port, family, type, proto, flags):
socket.gaierror: [Errno 11001] getaddrinfo failed
>>> socket.getaddrinfo('0177.0.0.1', 5000)
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "D:\anaconda3\lib\socket.py", line 748, in getaddrinfo
    for res in _socket.getaddrinfo(host, port, family, type, proto, flags):
socket.gaierror: [Errno 11001] getaddrinfo failed
```

如果是这么回事的话，某些情况下IP的正则匹配，是不是又能焕发青春了？当然并不是何种情况都可以这么理解，比如使用`redirect`，django中的`HttpResponseRedirect`跳转的时候，浏览器解析是没问题的。

requests库的限制方法，可以查看phithon大佬的一篇文章：https://www.leavesongs.com/PYTHON/defend-ssrf-vulnerable-in-python.html#

django有一个函数是`is_safe_url`，如果我们的资源服务器是一个固定地址，只需要较少的域名限制的时候，可以使用此函数来进行一个白名单的限制。参数`set_url`可以是一个列表。

```python
set_url = settings.SAFE_URL
def SSRF(request):
    if request.GET.get('url'):
        url = request.GET.get('url')
        if is_safe_url(url, set_url):
            text = urllib.request.urlopen(url)
            body = text.read().decode('utf-8')
            return render(request, 'ssrf.html', {'file':body})
        else:
            return HttpResponse('不合法地址')
    else:
        return HttpResponse('请输入url')

```

只不过这个函数出过一个漏洞`CVE-2017-7233`，原因是对域名分割的时候用的是`urllib.parse.urlparse`。判断的时候是利用的如下一条语句，可以看到只要满足and前后任意一个条件，就会返回True。

```python
((not url_info.netloc or url_info.netloc == host) and
(not url_info.scheme or url_info.scheme in ['http', 'https']))
```

而urlparse分割非期望参数的时候会出现以下情况。

```
>>> urllib.parse.urlparse('http:www.baidu.com')
ParseResult(scheme='http', netloc='', path='www.baidu.com', params='', query='', fragment='')
>>> urllib.parse.urlparse('http:/www.baidu.com')
ParseResult(scheme='http', netloc='', path='/www.baidu.com', params='', query='', fragment='')
>>> urllib.parse.urlparse('ht:888')
ParseResult(scheme='', netloc='', path='ht:888', params='', query='', fragment='')
>>> urllib.parse.urlparse('http:888')
ParseResult(scheme='http', netloc='', path='888', params='', query='', fragment='')
>>> urllib.parse.urlparse('https:888')
ParseResult(scheme='', netloc='', path='https:888', params='', query='', fragment='')
```

所以利用`https:12345678`这种形式来达到满足`not url_info.netloc`和`not url_info.scheme`来达到返回Ture。从而进行限制绕过。此处必须是`https`，不然过不了函数中的一个判断

```python
if not url_info.netloc and url_info.scheme:
	return False
```

修复版本是增加这么一句，不管你又没有协议，最后保证至少有一个http，然后就没办法利用上面的`not url_info.scheme`了。

```python
if not url_info.scheme and url_info.netloc:
	scheme = 'http'
valid_schemes = ['https'] if require_https else ['http', 'https']
return ((not url_info.netloc or url_info.netloc in allowed_hosts) and
		(not scheme or scheme in valid_schemes))
```





