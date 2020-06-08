## CSRF

django正常使用的时候，提交表单是需要一个csrf_token的，并且默认的setting中也有一个csrf中间件`django.middleware.csrf.CsrfViewMiddleware`，但是如果类似如下，使用`@csrf_exempt`来做一个例外的话，就会失去token保护

```Python
@csrf_exempt
def CSRF(request):
    if request.method == "POST":
```

当然如果设置中去掉了默认的中间件，需要查看是否给POST的方法中添加了`@csrf_protect`，来增加一个token防护。

```Python
@csrf_protect
def CSRF(request):
    if request.method == "POST":
```

在使用csrf中间件的时候，只要在关键的请求操作处没有使用了`@csrf_exempt`，如果去除了中间件，关键请求处查看是否都有做`@csrf_protect`

至于flask，请求中是没有关于csrf的默认防护的

```Python
@app.route('/csrf', methods=["GET","POST"])
def CSRF():
    if request.method == "POST":
        name = request.values.get('name')
        email = request.values.get('email')
```

### 修复代码

django中只要默认的中间件没有去除，并且没有增加`@csrf_exempt`来取消防护，就不会有问题，虽然前两年出现过`CVE-2016-7401`。只不过需要使用Google Analytics来做数据统计，使用基于Cookie的CSRF防护机制。影响django小于1.9.10的版本。

flask有一种使用跟django类似的方式，`flask_wtf.csrf`，实现让所有模块都接收csrf保护`CsrfProtect(app)`，如果在某个请求中使用了`@csrf.exempt`，做用跟django中的csrf例外一样，取消csrf防护。

```
from flask_wtf.csrf import CSRFProtect

CSRFProtect(app)  #保护全部view
```

如果没有如上的使用保护，也可以使用如下的惰性保护，因为他也有一个取消的装饰器`@csrf.exempt`，所以也需要查看是否设置了取消

```Python
def create_app():
    app = Flask(__name__)
    csrf.init_app(app)
```

官方使用方式：http://www.pythondoc.com/flask-wtf/csrf.html