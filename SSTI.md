## SSTI

模版注入常在flask和jinja2模板中出现，先看一段代码

```python
def ssti():
    if request.values.get('name'):
        name = request.values.get('name')
        template = "<p>%s<p1>" %name
        return render_template_string(template)
        
        #template = Template('<p>%s<p1>' %name)
        #return template.render()
    else:
        return render_template_string('<p>输入name值</p>')
```

其中大概有两个点是值得在意的，一个是格式化字符串，另一个是函数`render_template_string`。其是这两个更像是配合利用，像这么使用就不会有这个问题

```python
def ssti():
    if request.values.get('name'):
        name = request.values.get('name')
        template = "<p>{{ name }}<p1>"
        return render_template_string(template, name=name)
    else:
        return render_template_string('<p>输入name值</p>')
```

这么看的话，问题是出在格式化字符串上，而非某个函数上。格式化字符串的问题就是在于，是否传入是字符串还是一个模板语句。当使用格式化字符换，传入一个`{{ config }}`这样的值的时候，由于字符串的拼接替换，导致传入模板中的时候，被当作一个合法语句执行。而正常取值的时候，是先传入模板语句再进行字符串的解析，函数会把参数当作字符串处理。

当然出于安全考虑，模板引擎基本上都是拥有沙盒的，模板注入并不会直接解析python代码造成任意代码执行，所以想要利用这个问题，就需要配合沙箱逃逸来使用。沙箱逃逸这一块涉及的太多，有关资料也很多，就不多说。

之前也写过一篇[python 沙箱逃逸与SSTI](https://misakikata.github.io/2020/04/python-沙箱逃逸与SSTI/)。常见的利用比如这个执行命令的POC。

```
().__class__.__mro__[-1].__subclasses__()[72].__init__.__globals__['os'].system('whoami')
```

在django中，使用一些IDE创建项目的时候可以很明显看到，使用的模板是`Django`模板，当然我们也可以使用jinja2模板，不过django自己的模板并是很少见过ssti这种问题，倒是由于格式化字符串导致信息泄露，如下使用两种格式化字符串才造成问题的情况。

```python
def SSTI(request):
    if request.GET.get('name'):
        name = request.GET.get('name')
        template = "<p>user:{user}, name:%s<p1>" %name
        return HttpResponse(template.format(user=request.user))
    else:
        return HttpResponse('<p>输入name值</p>')
```

其中，当name传入`{user.password}`会读取到登陆用户的密码，此处使用管理员账号。那么为什么会传入的参数是name，而下面解析的时候被按照变量来读取了。

使用`format`来格式化字符串的时候，我们设定的user是等于`request.user`，而传入的是`{user.password}`，相当于template是`<p>user:{user}, name:{user.password}<p1>`，这样再去格式化字符串就变成了，`name:request.user.password`，导致被读取到信息。

在`format`格式符的情况下，出现ssti的情况也极少，比如使用如下代码，只能获得一个eval函数调用，`format`只能使用点和中括号，导致执行受到了限制。

```
{user.__init__.__globals__[__builtins__][eval]}
```

p牛给过两个代码用来利用django读取信息

```
http://localhost:8000/?email={user.groups.model._meta.app_config.module.admin.settings.SECRET_KEY}
http://localhost:8000/?email={user.user_permissions.model._meta.app_config.module.admin.settings.SECRET_KEY}
```

再找几个也可以使用的，上面都是直接使用auth模块来执行，因此可以先使用`{user.groups.model._meta.apps.app_configs}`找到包含的APP。

```
#其实这个跟上面的有些类似都是通过auth来读取
{user.groups.model._meta.apps.app_configs[auth].module.middleware.settings.SECRET_KEY}
#然后还可以换成sessions
{user.groups.model._meta.apps.app_configs[sessions].module.middleware.settings.SECRET_KEY}
#使用staticfiles
{user.groups.model._meta.apps.app_configs[staticfiles].module.utils.settings.SECRET_KEY}
```

### 修复代码

flask只要不把用户输入格式化字符串和`render_template_string`一起使用就可以降低风险，建议可以直接使用`render_template`，使用模板文件。

django使用`render`即可，由于函数原因，并不直接支持格式化字符串。

如果需要使用字符串，或者并不是直接使用框架中的函数。还有一种是jinja2的sandbox，同样可以降低风险。不过sandbox也出现过被绕过的情况，使用的时候要注意版本。

```python
def ssti():
    if request.values.get('name'):
        env = SandboxedEnvironment()
        name = request.values.get('name')
        #template = env.get_template('hello.html')
    	#template.render(name='Geng WenHao')
        return env.from_string(("<p>{name}<p1>").format(name=name)).render()
    else:
        return render_template_string('<p>输入name值</p>')
```



有兴趣的可以看几篇关于沙箱和SSTI利用的文章：

https://www.cnblogs.com/tr1ple/p/9415641.html

https://xz.aliyun.com/t/7746

https://www.leavesongs.com/PENETRATION/python-string-format-vulnerability.html

https://xz.aliyun.com/t/52

https://www.mi1k7ea.com/2019/06/02/%E6%B5%85%E6%9E%90Python-Flask-SSTI/