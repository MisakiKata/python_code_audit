import errno
import zipfile
from flask import Flask, Response, request,render_template, render_template_string,make_response, abort, redirect, send_from_directory
import sqlite3, ssl, re, os
from werkzeug.utils import secure_filename
from models import User
from databases import db_session
from flask_wtf.csrf import CSRFProtect
from markupsafe import Markup, escape
import pycurl
from io import BytesIO
import requests, urllib.request, urllib.parse
from requests_file import FileAdapter
import ipaddress,socket

app = Flask(__name__)
app.config['SECRET_KEY'] = '\xca\x0c\x86\x04\x98@\x02b\x1b7\x8c\x88]\x1b\xd7"+\xe6px@\xc3#\\'


@app.route('/xss')
def XSS():
    if request.args.get('name'):
        name = request.args.get('name')
        return Response("<p>name: %s</p>" %name)
        # 使用如下模板形式
        # return render_template('xss.html', name=name)
    else:
        return Response("<p>请输入name</p>")


@app.route('/sql')
def SQLi():
    if request.args.get('id'):
        id = request.args.get('id')
        con = sqlite3.connect('sql.db')
        c = con.cursor()
        username = c.execute('SELECT name FROM users WHERE id = %s;' % str(id)).fetchone()[0]
        email = c.execute('SELECT email FROM users WHERE id =' + str(id) + ';').fetchone()[0]

        # 使用如下代码修复
        # email = c.execute('SELECT email FROM users WHERE id = ?',[id]).fetchone()[0]
        # username = c.execute('SELECT name FROM users WHERE id = ?;', [id]).fetchone()[0]
        return Response("<p>用户为：%s</p>\n<p>邮箱为：%s</p>" % (username, email))
    else:
        return Response('<p>请输入用户id</p>')



# @app.route('/sql')
# def SQLi():
#     if request.args.get('id'):
#         id = request.args.get('id')
#         user = User.query.filter(User.id == id).first()
#         username, email = user.name, user.email
#
#         # 如下使用会产生漏洞
#         # sql = "SELECT name, email from users WHERE id = %s" % str(id)
#         # data = db_session.execute(sql).fetchone()
#         # username,email = data[0], data[1]
#
#         return Response("<p>用户为：%s</p>\n<p>邮箱为：%s</p>" % (username, email))
#     else:
#         return Response('<p>请输入用户id</p>')



# CSRFProtect(app)

@app.route('/csrf', methods=["GET","POST"])
def CSRF():
    if request.method == "POST":
        name = request.values.get('name')
        email = request.values.get('email')
        u = User(name=name, email=email)
        db_session.add(u)
        db_session.commit()
        return Response("Success")
    else:
        return render_template('csrf.html')


# @app.route('/ssrf')
# def SSRF():
#     if request.values.get('file'):
#         file = request.values.get('file')
#         curl = pycurl.Curl()
#         curl.setopt(curl.URL, file)
#         curl.setopt(curl.FOLLOWLOCATION, True)
#         curl.setopt(curl.MAXREDIRS, 3)
#         curl.setopt(curl.CONNECTTIMEOUT, 5)
#         buf = BytesIO()
#         curl.setopt(curl.WRITEDATA, buf)
#         curl.perform()
#         curl.close()
#         body = buf.getvalue()
#         return render_template('ssrf.html', file = body.decode('utf-8'))
#     else:
#         return Response('<p>请输入file地址</p>')

@app.route('/ssrf')
def SSRF():
    if request.values.get('file'):
        file = request.values.get('file')
        req = urllib.request.urlopen(file)
        body = req.read().decode('utf-8')
        return render_template('ssrf.html', file=body)
    else:
        return Response('<p>请输入file地址</p>')


# @app.route('/ssrf')
# def SSRF():
#     if request.values.get('file'):
#         file = request.values.get('file')
#         req = requests.get(file)
#         return render_template('ssrf.html', file=req.content.decode('utf-8'))
#     else:
#         return Response('<p>请输入file地址</p>')

@app.route('/location')
def location():
    return render_template('ssrf.html'), 302, [('Location','http://www.baidu.com')]

# urllib 的修复形式
# class Redict(urllib.request.HTTPRedirectHandler):
#     def newurls(self, url):
#         file = urllib.parse.urlparse(url).hostname
#         name = socket.gethostbyname(file)
#         try:
#             if ipaddress.ip_address(name).is_private:
#                 return True     #私有
#             else:
#                 return False    #公有
#         except:
#             return True
#
#     def redirect_request(self, req, fp, code, msg, headers, newurl):
#         if not self.newurls(newurl):
#             return urllib.request.Request(newurl)
#         else:
#             return abort(403)
#
# @app.route('/ssrf2')
# def location2():
#     if request.values.get('file'):
#         file = request.values.get('file')
#         try:
#             opener = urllib.request.build_opener(Redict)
#             response = opener.open(file)
#         except:
#             return Response('地址不合法')
#         body = response.read().decode('utf-8')
#         return render_template('ssrf.html', file=body)
#     else:
#         return Response('<p>请输入file地址</p>')

import sys, io, subprocess, chardet

@app.route('/command')
def command():
    if request.values.get('cmd'):
        sys.stdout = io.StringIO()
        cmd = request.values.get('cmd')

        # s = subprocess.Popen('ping -n 4 '+cmd, shell=True, stdout=subprocess.PIPE)
        # stdout = s.communicate()
        # return Response('<p>输入的值为：%s</p>' %str(stdout[0], encoding=chardet.detect(stdout[0])['encoding']))
        return Response('<p>输入的值为：%s</p>' %str(eval(cmd)))  #__import__(%22os%22).popen(%27whoami%27).read()
        # return Response('<p>输入的值为：%s</p>' %str(exec(cmd)))    #import%20os;os.system(%27whoami%27)
    else:
        return Response('<p>请输入cmd值</p>')


@app.route('/read')
def readfile():
    if request.values.get('file'):
        file = request.values.get('file')
        req = urllib.request.urlopen(file)
        return Response(req.read().decode('utf-8'))
    else:
        return Response('<p>请输入file地址</p>')


@app.route('/uploadfile/<path:file>')
def readupfile(file):
    with open('./uploadfile/%s' %file, 'rb') as f:
        content = f.read()
    return Response(content)
    # return send_from_directory(os.path.join(os.path.dirname(__file__), 'uploadfile'), file)


# @app.route('/uploadfile/<path:file>')
# def readfile(file):
#     dir = os.path.abspath(os.path.join('/uploadfile', file))
#     if os.path.dirname(dir) == os.path.join(os.getcwd(), 'uploadfile'):
#         with open(dir, 'r') as f:
#             content = f.read()
#         return Response(content)
#     else:
#         return Response('文件读取失败')


@app.route('/upload', methods=['GET','POST'])
def upload():
    if request.files.get('filename'):
        file = request.files.get('filename')
        upload_dir = os.path.join(os.path.dirname(__file__), 'uploadfile')
        dir = os.path.join(upload_dir, file.filename)
        file.save(dir)
        return render_template('upload.html', file='上传成功')
    else:
        return render_template('upload.html', file='选择文件')


# ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg', 'gif'])  #白名单
# app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploadfile')
#
# def allowed_file(filename):
#     return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS
#
# @app.route('/upload', methods=['GET','POST'])
# def upload():
#     if request.files.get('filename'):
#         file = request.files.get('filename')
#         if file and allowed_file(file.filename):
#             filename = secure_filename(file.filename)
#             file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
#             return render_template('upload.html', file='上传成功')
#         else:
#             return render_template('upload.html', file='不允许类型')
#     else:
#         return render_template('upload.html', file='选择文件')


# @app.route('/zip', methods=['GET','POST'])
# def zip():
#     if request.files.get('filename'):
#         zip_file = request.files.get('filename')
#         files = []
#         with zipfile.ZipFile(zip_file, "r") as z:
#             for fileinfo in z.infolist():
#                 filename = fileinfo.filename
#                 dat = z.open(filename, "r")
#                 files.append(filename)
#                 outfile = os.path.join(app.config['UPLOAD_FOLDER'], filename)
#                 if not os.path.exists(os.path.dirname(outfile)):
#                     try:
#                         os.makedirs(os.path.dirname(outfile))
#                     except OSError as exc:
#                         if exc.errno != errno.EEXIST:
#                             print("\n[WARN] OS Error: Race Condition")
#                 if not outfile.endswith("/"):
#                     with io.open(outfile, mode='wb') as f:
#                         f.write(dat.read())
#                 dat.close()
#         return render_template('upload.html', file=files)
#     else:
#         return render_template('upload.html', file='选择文件')

from jinja2 import Template

@app.route('/ssti')
def ssti():
    if request.values.get('name'):
        name = request.values.get('name')
        template = "<p>{name}<p1>".format(name=name)
        return render_template_string(template)

        # template = Template('<p>%s<p1>' %name)
        # return template.render()

        # template = "<p>{{ name }}<p1>"
        # return render_template_string(template, name=name)
    else:
        return render_template_string('<p>输入name值</p>')

# from jinja2.sandbox import SandboxedEnvironment
#
# @app.route('/ssti')
# def ssti():
#     if request.values.get('name'):
#         env = SandboxedEnvironment()
#         name = request.values.get('name')
#         return env.from_string(("<p>{name}<p1>").format(name=name)).render()
#     else:
#         return render_template_string('<p>输入name值</p>')

from lxml import etree
import lxml.objectify
import xml.dom.minidom, xml.dom.pulldom

@app.route('/xxe',methods=['POST', 'GET'])
def xxe():
    # tree = etree.parse('xml.xml')
    tree = lxml.objectify.parse('xml.xml', etree.XMLParser(resolve_entities=False))
    return etree.tostring(tree.getroot())

    # xmls = """<?xml version="1.0" encoding="UTF-8"?>
    #         <!DOCTYPE title [
    #         <!ELEMENT data (#PCDATA)>
    #         <!ENTITY file SYSTEM "file:///c:/windows/win.ini" >]>
    #         <title>&file;</title>"""
    # tree = etree.fromstring(xml, etree.XMLParser(resolve_entities=False))
    # return etree.tostring(tree)

    # doc = xml.dom.pulldom.parse('xml.xml')
    # for event, node in doc:
    #     doc.expandNode(node)
    #     nodes = node.get
    # return Response(nodes)

import pickle

@app.route('/ser')
def ser():
    ser = b'\x80\x03cnt\nsystem\nq\x00X\x06\x00\x00\x00whoamiq\x01\x85q\x02Rq\x03.'
    s = pickle.loads(ser)
    return Response(s)


@app.route('/urlbypass')
def urlbypass():
    if request.values.get('url'):
        url = request.values.get('url')
        return redirect(url)
    else:
        return Response('请输入跳转的url')

# def urlbypass():
#     if request.values.get('url'):
#         url = request.values.get('url')
#         if url.endswith('baidu.com'):
#             return redirect(url)
#         else:
#             return Response('不允许域名')
#     else:
#         return Response('请输入跳转的url')



if __name__ == '__main__':
    app.run()
