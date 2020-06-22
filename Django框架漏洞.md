### CVE-2018-14574

影响范围：1.11.0 <= version < 1.11.15 和 2.0.0 <= version < 2.0.8

开放重定向：https://www.djangoproject.com/weblog/2018/aug/01/security-releases/

此漏洞有两个前提条件，其中是需要一个中间件`django.middleware.common.CommonMiddleware`，同时需要

`APPEND_SLASH=True`，这个设置是在目录末尾加斜杠。当我们设定一个常规路由，如下时

```
path('index/', views.index),
```

访问`/index`会跳转到`/index/`地址，添加反斜线。目的就是为了去匹配上面设置的index路径。

```
HTTP/1.1 301 Moved Permanently
Date: Wed, 10 Jun 2020 03:11:54 GMT
Server: WSGIServer/0.2 CPython/3.7.0
Content-Type: text/html; charset=utf-8
Location: /index/
```

设置为False的时候，访问`/index`只会访问此地址，如果没有匹配到地址，返回404。

把路由设置为类似如下情况，`re_path(r'(.*)/$', views.index),`，访问任意地址都会跳转

```
HTTP/1.1 301 Moved Permanently
Date: Wed, 10 Jun 2020 05:44:38 GMT
Server: WSGIServer/0.2 CPython/3.7.0
Content-Type: text/html; charset=utf-8
Location: /qqq/
```

访问`//www.baidu.com`，这时候显示为跳转

```
HTTP/1.1 301 Moved Permanently
Date: Wed, 10 Jun 2020 05:50:34 GMT
Server: WSGIServer/0.2 CPython/3.7.0
Content-Type: text/html; charset=utf-8
Location: //www.baidu.com/
Content-Length: 0
```

但是由于路径原因，浏览器会把跳转的地址识别为域名，从而导致任意跳转。那么这么跟`APPEND_SLASH=True`有什么关系，其实就是为了让他来触发没有斜杠，而自动添加斜杠跳转，来触发301。否则就是404。

涉及的中间件为common.py文件中的CommonMiddleware类。主要是`process_request`和`process_response`

，`process_request`中的参数`request`和视图函数中的request是一样的，通过中间件先处理发送请求。

```python
    def process_request(self, request):
        """
        Check for denied User-Agents and rewrite the URL based on
        settings.APPEND_SLASH and settings.PREPEND_WWW
        """

        # Check for denied User-Agents
        if 'HTTP_USER_AGENT' in request.META:
            for user_agent_regex in settings.DISALLOWED_USER_AGENTS:
                if user_agent_regex.search(request.META['HTTP_USER_AGENT']):
                    raise PermissionDenied('Forbidden user agent')

        # Check for a redirect based on settings.PREPEND_WWW
        host = request.get_host()
        must_prepend = settings.PREPEND_WWW and host and not host.startswith('www.')
        redirect_url = ('%s://www.%s' % (request.scheme, host)) if must_prepend else ''
        
        if self.should_redirect_with_slash(request):
            path = self.get_full_path_with_slash(request)
        else:
            path = request.get_full_path()

        # Return a redirect if necessary
        if redirect_url or path != request.get_full_path():
            redirect_url += path
            return self.response_redirect_class(redirect_url)
```

函数先分析请求，获取域名然后判断域名是否有`www`开头，这里`PREPEND_WWW`做用跳转的时候给域名添加www后跳转，比如访问`/qqq`，跳转到`http://www.127.0.0.1:8000/qqq/`，默认是False。

```
HTTP/1.1 301 Moved Permanently
Date: Wed, 10 Jun 2020 06:39:57 GMT
Server: WSGIServer/0.2 CPython/3.7.0
Content-Type: text/html; charset=utf-8
Location: http://www.127.0.0.1:8000/qqq/
```

下面调用`should_redirect_with_slash`，查看函数的意思。不过注释已经说明白就是一个根据设置添加斜杠然后再去验证路径是否有效访问，仍然不能匹配的则返回404。

```python
    def should_redirect_with_slash(self, request):
        """
        Return True if settings.APPEND_SLASH is True and appending a slash to
        the request path turns an invalid path into a valid one.
        """
        if settings.APPEND_SLASH and not request.path_info.endswith('/'):
            urlconf = getattr(request, 'urlconf', None)
            return (
                not is_valid_path(request.path_info, urlconf) and
                is_valid_path('%s/' % request.path_info, urlconf)
            )
        return False
```

验证路径合法后，则开始继续全路径获取，debug模式下是不能进行其他的请求方法，至少是看起来只能使用GET方法，`request.get_full_path(force_append_slash=True)`获取当前的请求的全路径加斜杠返回。当请求的是`/index`的时候，到这里已经修改为`/index/`。

```python
    def get_full_path_with_slash(self, request):
        """
        Return the full path of the request with a trailing slash appended.

        Raise a RuntimeError if settings.DEBUG is True and request.method is
        POST, PUT, or PATCH.
        """
        new_path = request.get_full_path(force_append_slash=True)
        if settings.DEBUG and request.method in ('POST', 'PUT', 'PATCH'):
            raise RuntimeError(
                "You called this URL via %(method)s, but the URL doesn't end "
                "in a slash and you have APPEND_SLASH set. Django can't "
                "redirect to the slash URL while maintaining %(method)s data. "
                "Change your form to point to %(url)s (note the trailing "
                "slash), or set APPEND_SLASH=False in your Django settings." % {
                    'method': request.method,
                    'url': request.get_host() + new_path,
                }
            )
        return new_path
```

因为`PREPEND_WWW`设置的原因，不修改的情况下`redirect_url`为空，判断`path != request.get_full_path()`的时候，`path`为`/index/`，而`request.get_full_path()`没有添加反斜杠所以为请求的路径`/index`，不相等则赋值给`redirect_url`，返回一个跳转。

整个流程走下来，大概就知道问题出在哪里， 获取跳转路径的时候，是从域名后整个路径地址全部返回。使用urlparse解释获取路径

```python
>>> urllib.parse.urlparse('http://127.0.0.1//www.baidu.com')
ParseResult(scheme='http', netloc='127.0.0.1', path='//www.baidu.com', params='', query='', fragment='')
```

获取new_path 后则直接给响应跳转。如果需要减轻这个问题，还可以设置`PREPEND_WWW=True`带域名跳转。但对多级域名和IP地址就不好用。

官方修补的方式是从`from django.utils.http import escape_leading_slashes`导入一个编码斜杠函数。

在`get_full_path_with_slash`中判断获取到的路径是否有两个斜杠，有的话则返回一个编码的形式。

```python
def escape_leading_slashes(url):
    """
    If redirecting to an absolute path (two leading slashes), a slash must be
    escaped to prevent browsers from handling the path as schemaless and
    redirecting to another host.
    """
    if url.startswith('//'):
        url = '/%2F{}'.format(url[2:])
    return url
```

### CVE-2020-7471

受影响的版本：Django 1.11.x < 1.11.28，Django 2.2.x < 2.2.10，Django 3.0.x < 3.0.3

postgres的sql注入：https://www.djangoproject.com/weblog/2020/feb/03/security-releases/

环境取自：https://github.com/Saferman/CVE-2020-7471

根据官方显示，是使用`django.contrib.postgres.aggregates.StringAgg`分隔符导致的注入。

配置好数据库，正确连接后开始复现一下。为了方便调试，先配置view

```
def select(request):
    if request.GET.get('id'):
        id = request.GET.get('id')
        str = Info.objects.all().values('gender').annotate(mydefinedname=StringAgg('name', delimiter=id))
        return HttpResponse(str)
    else:
        return HttpResponse('提交id')
```

然后运行脚本存储数据。

请求如下数据的时候`/select/?id=%2d%27%29%20%41%53%20%22%6d%79%64%65%66%69%6e%65%64%6e%61%6d%65%22%20%46%52%4f%4d%20%22%76%75%6c%5f%61%70%70%5f%69%6e%66%6f%22%20%47%52%4f%55%50%20%42%59%20%22%76%75%6c%5f%61%70%70%5f%69%6e%66%6f%22%2e%22%67%65%6e%64%65%72%22%20%4c%49%4d%49%54%20%32%20%4f%46%46%53%45%54%20%31%20%2d%2d`会触发注入的效果。

```
HTTP/1.1 200 OK
Date: Wed, 10 Jun 2020 09:06:22 GMT
Server: WSGIServer/0.2 CPython/3.7.0
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 48

{'gender': 'male', 'mydefinedname': 'li-\\zhao'}
```

`annotate`数据聚合函数，比如我们有一个获取某个类别的数量。一般使用`Info.objects.filter('name').count()`，使用聚合函数就可以`Info.objects.annotate(num=count('name'))`这样就设定一个num属性，可以利用模板来获取数据。

`StringAgg`对应SQL中的标准函数`String_agg`，一般需要两个参数，一个是需要聚合的值，一个是用来分割的字符。比如上面的POC给的意思，`Info.objects.all().values('gender')`是以`gender`列做为参数来获取数据，获取到的为`{'gender': '123'}{'gender': 'male'}..`，通过聚合函数设定一个新的属性`mydefinedname`，参数为以`-`为分割符的`name`字段聚合。结果`'gender': 'male', 'mydefinedname': 'li-zhao'}..`因为有两个`male`的属性，所以`li-zhao`聚合在一起并用横杠分割。

```python
payload = '-'
results = Info.objects.all().values('gender').annotate(mydefinedname=StringAgg('name', delimiter=payload))
```

看到这里就知道官方说的，聚合函数分隔符导致漏洞产生的问题，就是`delimiter`参数没有限制输入。看一下官方Github的修改代码：https://github.com/django/django/commit/505826b469b16ab36693360da9e11fd13213421b

先在`StringAgg`上去掉了`template`变量中的分割符占位符。下面又把分隔符给转换字符串，再用Value来处理，此函数是一个表达最小可能的属性，当表示整数、字符串、布尔值的时候，可以使用Value来处理。

```python
class StringAgg(OrderableAggMixin, Aggregate):
    function = 'STRING_AGG'
    # template = "%(function)s(%(distinct)s%(expressions)s, '%(delimiter)s'%(ordering)s)"
    template = '%(function)s(%(distinct)s%(expressions)s %(ordering)s)'
    allow_distinct = True

    def __init__(self, expression, delimiter, **extra):
        # super().__init__(expression, delimiter=delimiter, **extra)
        delimiter_expr = Value(str(delimiter))
        super().__init__(expression, delimiter_expr, **extra)

    def convert_value(self, value, expression, connection):
        if not value:
```

函数继承的`OrderableAggMixin`把对应的`expression`转换成打包成元组了。通过一通有的没的，就发现as_sql处理成以下形式：

`'STRING_AGG("vul_app_info"."name", \'-\') AS "mydefinedname" FROM "vul_app_info" GROUP BY "vul_app_info"."gender" LIMIT 2 OFFSET 1 --\') AS "mydefinedname"'`

最后执行的SQL语句为，因为以下是字符串，所以转义符的原因这个SQL并不能直接执行：

`'SELECT "vul_app_info"."gender", STRING_AGG("vul_app_info"."name", \'-\') AS "mydefinedname" FROM "vul_app_info" GROUP BY "vul_app_info"."gender" LIMIT 2 OFFSET 1 --\') AS "mydefinedname" FROM "vul_app_info" GROUP BY "vul_app_info"."gender"'`

去除部分不需要的东西，实际执行的SQL为：

```sql
SELECT "vul_app_info"."gender", STRING_AGG("vul_app_info"."name", '-') AS "mydefinedname" FROM "vul_app_info" GROUP BY "vul_app_info"."gender" LIMIT 2 OFFSET 1
```

到此，可以看出来POC是把程序后来编译的SQL注释掉，直接从输入中给替代掉了。由于修复代码中使用了Value，分隔符成为了一个Value类型的字符串`'-\') AS "mydefinedname" FROM "vul_app_info" GROUP BY "vul_app_info"."gender" LIMIT 2 OFFSET 1 --'`，后面的拼接也变成了占位符的形式。

sql先处理成`'STRING_AGG("vul_app_info"."name", %s ) AS "mydefinedname"'`。最后SQL为

```sql
SELECT "vul_app_info"."gender", STRING_AGG("vul_app_info"."name", %s ) AS "mydefinedname" FROM "vul_app_info" GROUP BY "vul_app_info"."gender"
```

使用数据库中`cursor.execute(sql, params)`来执行编译语句防止注入。

