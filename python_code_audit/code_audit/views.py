import html
from django.http import Http404
from django.shortcuts import render, HttpResponse, HttpResponseRedirect, redirect
import sqlite3
from django.contrib.auth.models import User
from django.views.generic import View
from code_audit.models import File
from code_audit.form import AddUserForm
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.utils.http import is_safe_url
import urllib.request
from django.conf import settings
import os,io,sys, ping3
# Create your views here.


def XSS(request):

    if request.GET.get('name'):
        name = request.GET.get('name')
        return HttpResponse("<p>name: %s</p>" %name)
        # return HttpResponse("<a href='%s'>aaaa</a>" %name)

        # 使用模板显示
        # return render(request, 'index.html', locals())
    else:
        return HttpResponse("<p>请输入name</p>")

#
# def SQLi(request):
#     if request.GET.get('id'):
#         id = request.GET.get('id')
#         con = sqlite3.connect('db.sqlite3')
#         c = con.cursor()
#         username = c.execute('SELECT username FROM auth_user WHERE id = %s;' %str(id)).fetchall()
#         email = c.execute('SELECT email FROM auth_user WHERE id ='+str(id)+';').fetchall()
#
#         # 可以使用如下的参数位设置预编译语句
#         # email = c.execute('SELECT email FROM auth_user WHERE id = ?',[id]).fetchone()[0]
#         # username = c.execute('SELECT username FROM auth_user WHERE id = ?;', [id]).fetchone()[0]
#
#         return HttpResponse("<p>用户为：%s</p>\n<p>邮箱为：%s</p>" %(username,email))
#     else:
#         return HttpResponse('<p>请输入用户id</p>')


#   或者使用django自带的api来操作数据库
def SQLi(request):
    if request.GET.get('id'):
        id = request.GET.get('id')
        user = User.objects.get(id=str(id))
        username = user.username
        email = user.email
        return HttpResponse("<p>用户为：%s</p>\n<p>邮箱为：%s</p>" %(username,email))
    else:
        return HttpResponse('<p>请输入用户id</p>')


@csrf_exempt
def CSRF(request):
    if request.method == "POST":
        form = AddUserForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['name']
            email = form.cleaned_data['email']
            u = User(username=name, email=email)
            u.save()
            return HttpResponse('Success')
        else:
            return HttpResponse('Fail')
    else:
        form = AddUserForm()
        user = User.objects.all()
        return render(request, 'form.html', {'user':user,'form': form})


set_url = settings.SAFE_URL
def SSRF(request):
    if request.GET.get('url'):
        url = request.GET.get('url')
        if is_safe_url(url, set_url):
            text = urllib.request.urlopen(url)
            body = text.read().decode('utf-8')
            return render(request, 'ssrf.html', {'file' : body})
        else:
            return HttpResponse('不合法地址')
    else:
        return HttpResponse('请输入url')


def COMMAND(request):
    if request.GET.get('ip'):
        ip = request.GET.get('ip')
        flag = os.system('ping -n 1 %s' %ip)
        return HttpResponse('<p>%s</p>' %(flag))   #127.0.0.1&&whoami
    else:
        return HttpResponse('<p>请输入IP地址</p>')

# import subprocess, shlex, chardet
#
# def COMMAND(request):
#     if request.GET.get('ip'):
#         ip = request.GET.get('ip')
#         cmd = 'ping -n 4 %s' %shlex.quote(ip)
#         flag = subprocess.run(cmd, shell=False, stdout=subprocess.PIPE)
#         stdout = flag.stdout
#         return HttpResponse('<p>%s</p>' %str(stdout, encoding=chardet.detect(stdout)['encoding']))   #127.0.0.1&&whoami
#     else:
#         return HttpResponse('<p>请输入IP地址</p>')

# def READFILE(request):
#     if request.GET.get('file'):
#         file = request.GET.get('file')
#         file = open(file)
#         return HttpResponse(file)
#     else:
#         return HttpResponse('<p>请输入file地址</p>')


def READFILE(request):
    file = request.GET.get('path')
    path = os.path.join('/var/www/images/', file)  #images为限制的读取目录
    if os.path.abspath(path).startswith('/var/www/images/') is False:
        raise Http404
    else:
        with open(path, "rb") as f:
            content = f.read()
        return HttpResponse(content)



def UPLOADFILE(request):
    if request.method == 'GET':
        return render(request, 'upload.html', {'file':'选择文件'})
    elif request.method == 'POST':
        dir = os.path.join(os.path.dirname(__file__), '../static/upload')
        file = request.FILES.get('filename')
        name = os.path.join(dir, file.name)
        print(file, name)
        with open(name, 'wb') as f:
            f.write(file.read())
        return render(request, 'upload.html', {'file':'上传成功'})

import uuid, time

# ALLOWED_EXTENSIONS = settings.ALLOWED_EXTENSIONS
# MAX_SIZE = settings.MAX_FILE_SIZE
# UPLOAD_FOLDER = settings.UPLOAD_FOLDER
#
# def allowed_file(filename):
#     if '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS:
#         filext = filename.rsplit('.', 1)[1]
#         return str(uuid.uuid5(uuid.NAMESPACE_DNS, str(time.time())))+"."+filext
#     else:
#         return None
#
# def UPLOADFILE(request):
#     if request.method=='GET':
#         return render(request,'upload.html')
#     else:
#         img=request.FILES.get('filename')
#         if img.size < MAX_SIZE and allowed_file(img.name):
#             name = UPLOAD_FOLDER+allowed_file(img.name)
#             f=open(name,'wb')
#             for line in img.chunks():
#                 f.write(line)
#             f.close()
#             return render(request, 'upload.html', {'file':'上传成功'})
#         else:
#             return render(request, 'upload.html', {'file':"不允许的类型或者大小超限"})


# class IndexView(View):
#     def filename(self, file):
#         if '.' in file and file.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS:
#             filext = file.rsplit('.', 1)[1]
#             return str(uuid.uuid5(uuid.NAMESPACE_DNS, file))+"."+filext
#         else:
#             return None
#     def get(self,request):
#         return render(request,'upload.html')
#     def post(self,request):
#         myfile = request.FILES.get('filename')
#         try:
#             if myfile.size <= MAX_SIZE and self.filename(myfile.name):
#                 myfile.name = self.filename(myfile.name)
#                 File.objects.create(filename=myfile.name, filext=myfile).save()
#                 return render(request, 'upload.html', {'file':'上传成功'})
#             else:
#                 return render(request, 'upload.html', {'file':'不允许的类型或大小超限'})
#         except Exception as e:
#             return render(request,'upload.html', {'file':"不允许的类型或大小超限"})


def SSTI(request):
    if request.GET.get('name'):
        name = request.GET.get('name')
        template = "<p>user:{user}, name:%s<p1>" %name
        return HttpResponse(template.format(user=request.user))
    else:
        return HttpResponse('<p>输入name值</p>')


import logging,logging.config

def INFOR(request):
    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    infor = {'age': 12, 'name': 'join'}
    try:
        open('exist', 'r')
    except (SystemExit, KeyboardInterrupt):
        raise
    except Exception as e:
        logger.error('Failed to open file', exc_info=True)

    return HttpResponse(logger.debug(infor))


import urllib.parse

def BYPASS(request):
    if request.GET.get('url'):
        url = request.GET.get('url')    #https:3026530571
        if urllib.parse.urlparse(url).netloc and urllib.parse.urlparse(url).netloc in set_url:
            return HttpResponseRedirect(url)
        elif urllib.parse.urlparse(url).netloc == '':
            path = urllib.parse.urlparse(url).path
            return HttpResponseRedirect(path)
        else:
            return HttpResponse('不允许域名')
    else:
        return HttpResponse('请输入url')

