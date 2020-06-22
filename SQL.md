## SQL

SQL注入的存在类型多半是拼接代码的过程中出现，类似如下形式
```
http://www.aaa.com?id=1
"SELECT * FROM user WHERE id='"+id+"';"
```
Python中存在注入问题可能更多的是利用格式化字符串拼接的问题，比如
```
sql = "SELECT * FROM user WHERE id=%s;" %id
con.execute(sql)
```

比如在django中的示例代码：

```Python
username = c.execute('SELECT username FROM auth_user WHERE id = %s;' %str(id)).fetchall()
```

如果传入参数进行拼接，就会产生SQL 注入。

在flask上经常使用的SQLAlchemy，它可以像django一样，创建一个表模型，通过api来操作数据库。查看示例代码中的实现

比如当使用`user = User.query.filter(User.id == id)`的时候产生的是如下的语句

```Python
SELECT users.id AS users_id, users.name AS users_name, users.email AS users_email
FROM users
WHERE users.id = ?
```

这样使用还会出现注入嘛？正常使用是不会出现，但如果不正常使用，比如把上面的拼接语句跟SQLAlchemy结合使用该出现的还是会出现

```Python
sql = "SELECT name, email from users WHERE id = %s" %str(id)
data = session.execute(sql).fetchone()
```

那么是不是只要使用了标准的api接口，不采用拼接的形式就不会出现注入了。这里又涉及到一个词，叫正确使用，什么是正确使用，用phithon大佬的一篇文章，[Pwnhub Web题Classroom题解与分析](https://www.leavesongs.com/PENETRATION/pwnhub-web-classroom-django-sql-injection.html)

比如以下代码，没有采用拼接，也用的是标准的api接口，理论上是不存在注入的，但是此处却能达到注入的效果，问题就是filter没有按照正确的使用形式，传入的参数名是可控制的。

```Python
class LoginView(JsonResponseMixin, generic.TemplateView):
    template_name = 'login.html'

    def post(self, request, *args, **kwargs):
        data = json.loads(request.body.decode())
        stu = models.Student.objects.filter(**data).first()
        if not stu or stu.passkey != data['passkey']:
            return self._jsondata('账号或密码错误', 403)
        else:
            request.session['is_login'] = True
            return self._jsondata('登录成功', 200)
```

当使用IDE进行代码编写的时候，写入参数名会自动出现很多类似的字段`auther__username__exact=admin`，auther是表中的字段也是外键，username是transform，而exact是lookup。

区别是：transform表示“如何去找关联的字段”，lookup表示“这个字段如何与后面的值进行比对”。

所以上面提到的那个字段意思就是：在`author`外键连接的用户表中，找到`username`等于`admin`的字段。

生成的SQL语句就是`WHERE users.username = 'admin'`。对于上面那段代码，只要使用`{"passkey__contains":"a"}`，密码字段包含a就会造成注入。

### 字典注入

通常对数据操作的时候，是使用`User.objects.create(username=name)`这种形式，还有一种是利用字典进行数据操作，同样可以操作数据，但此时的问题就存在于字典键上，形式类似上面的参数名可控。

```python
dict = {'username':"admin", 'age':18}
User.objects.create(**dict)
```

### 二次注入

django数据库是ORM框架，使用django的数据库操作api的时候是可以防御SQL注入的，但是存在一种使用不当造成二次注入的情况，比如有此views

```python
def files(request):
    if request.GET.get('url'):
        url = request.GET.get('url')
        File.objects.create(filename=url)
        return HttpResponse('保存成功')
    else:
        filename = File.objects.get(pk=23).filename
        cur = connection.cursor()
        cur.execute("""select * from code_audit_file where filename='%s'""" %(filename))
        str = cur.fetchall()
        cur.close()
        return HttpResponse(str)
```

当我们保存字段`filename`的时候，如果字段是`' or '1'='1`，则会自动转义为`\' or \'1\'=\'1`，但是其中的单引号并不会被去除，而是全部当作一个字符串被保存。后面如果使用拼接的SQL语句，就会触发SQL注入

```
select * from code_audit_file where filename='' or '1'='1'
```

就会造成如上的SQL语句，导致SQL注入的产生。

列举几个django最近一年的几个SQL注入漏洞，[CVE-2020-7471](https://xz.aliyun.com/t/7218)，[CVE-2020-9402](https://xz.aliyun.com/t/7403)，[CVE-2019-14234](https://xz.aliyun.com/t/5896)

### 修复代码


怎么处理这种使用第三方数据库模块导致的漏洞，例如在sqlite3库中，execute是带有函数参数位，可以利用函数对传入值转译。
```
execute("SELECT *FROM user WHERE id=?", [id])
```
比如插入多条数据的时候
```Python
sql = 'insert into userinfo(user,pwd) values(%s,%s);'
data = [
    ('july', '147'),
    ('june', '258'),
]
cursor.executemany(sql, data)
```

示例代码中，django的处理方式有两种，如上的编译型语句，还有一种是django自身的ORM引擎，利用api来操作数据库，但是也要正确使用

```
user = User.objects.get(id=str(id))
```

如果使用如下拼接，就算是api还是会有问题

```Python
user = User.objects.raw('SELECT *FROM user WHERE id='+'"'+id+'"')
```

Django的查询语法难以简单的表达复杂的 `WHERE` 子句，对于这种情况, Django 提供了 `extra()` `QuerySet`修改机制 — 它能在 `QuerySet`生成的SQL从句中注入新子句。https://www.cnblogs.com/gaoya666/p/8877116.html

```Python
queryResult=models.Article.objects.extra(select={'is_recent': "create_time > '2018-04-18'"})
```

当没有正确使用的时候，还是会导致SQL注入的产生

```
User.objects.extra(WHERE=['id='+str(id)])  #错误使用
User.objects.extra(WHERE=['id=%s'], params=[str(id)])  #正确使用
```

flask可以使用编译语句外，还可以使用Sqlalchemy，详细查看示例代码，构建一个models后，可以使用类似django的方式来操作数据。

```Python
user = User.query.filter(User.id == id).first()
```

如果是插入的话，将会构建一个类似如下的编译语句

```
[SQL: INSERT INTO users (name, email) VALUES (?, ?)]
```

