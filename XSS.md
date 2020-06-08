## XSS

xss的出现某种程度上跟sql注入有些类似，都是对输入参数没有过滤和正确引用，导致输出的时候造成代码注入到页面。

例如：

```Python
name = request.GET.get('name')
return HttpResponse("<p>name: %s</p>" %name)
```

当参数直接输出到页面的时候就会产生xss。不过xss不一样的是，花样很多，不一的是上面显示的很直接，但很多地方不会这么直接的显示给你。只不过本质上是没处理输入直接输出导致。

在django上如下使用：

```Python
def XSS(request):
    if request.GET.get('name'):
        name = request.GET.get('name')
        return HttpResponse("<p>name: %s</p>" %name)
```

和flask上如下使用：

```Python
@app.route('/xss')
def XSS():
    if request.args.get('name'):
        name = request.args.get('name')
        return Response("<p>name: %s</p>" %name)
```

不过使用模板语言并不是百分百没问题，假设模板使用了`|safe`来处理输入。这种仍然会出现XSS。

```
return render_template('xss.html', name=name)

#使用safe来处理输入
<h1>Hello {{ name|safe }}!</h1>
```

### 修复代码

想防御XSS，有很多种选择了。比如django中的使用自带的模板形式。

```
return render(request, 'index.html', locals())
```

flask中：

```
return render_template('xss.html', name=name)
```

不过此处能使用的函数，最好不是`render_template_string`，准确的说是里面可以传入字符串，可能会产生XSS。重要的是控制不当还会产生模板注入。

或者使用一些编码函数来处理输入，比如escape。

```
>>> import html
>>> html.escape('<script>')
'&lt;script&gt;'
>>> html.unescape('&lt;script&gt;')
'<script>'
```

使用MarkupSafe:

```
>>> from markupsafe import escape
>>> escape('<script>alert(2)</script>')
Markup('&lt;script&gt;alert(2)&lt;/script&gt;')
```

但是使用不正确还是会产生问题，比如如下使用的时候就不会转义了。

```
>>> escape(Markup('<script>alert(2)</script>'))
Markup('<script>alert(2)</script>')
```

在输出属性为动态内容的时候，这种情况只能先做一次是否为正确url的判断在做输出。

```
<a href="{{ url }}">aaaa</a>
```

