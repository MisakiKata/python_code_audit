### PYC反编译

python文件在被import运行的时候会在同目录下编译一个pyc的文件，这个文件可以和py文件一样使用，为了下次快速加载存在。pyc文件就是字节码文件，同样还有pyo文件，这是一个优化文件格式，可以提高加载速度，减少容量。

比如这里用一个CTF的代码，使用python自带的`py_compile`编译，`python -m py_compile pyc.py`。

```python
# Embedded file name: secend.py
print "Welcome to Processor's Python Classroom Part 2!\n"
print "Now let's start the origin of Python!\n"
print 'Plz Input Your Flag:\n'
enc = raw_input()
len = len(enc)
enc1 = []
enc2 = ''
aaa = 'ioOavquaDb}x2ha4[~ifqZaujQ#'
for i in range(len):
    if i % 2 == 0:#2
        enc1.append(chr(ord(enc[i]) + 1))
    else:#1
        enc1.append(chr(ord(enc[i]) + 2))
 
s1 = []
for x in range(3):#encrypt the plain
    for i in range(len):#
        if (i + x) % 3 == 0:#swap the position
            s1.append(enc1[i])
 
enc2 = enc2.join(s1)
if enc2 in aaa: #another way to judge equal
    print "You 're Right!"
else:
    print "You're Wrong!"
    exit(0)
```

编译一个pyo文件。`python -O -m py_compile pyc.py`

编译完成后的字节码文件可以在一定程度上来防止代码泄露，但python的解释器开源特性，这种方式终究不能很完善的加密。有几种不错的反编译pyc字节码的工具。

#### uncompyle6

uncompyle6将Python字节码转换回等效的Python源代码。它支持从Python 1.0版到3.8版的字节码。

安装：`pip install uncompyle6`，或者去项目地址编译安装https://github.com/rocky/python-uncompyle6.git

反编译：`uncompyle6 pyc.pyc`即可，如果要输出到文件，重定向到文件即可。

#### Easy Python Decompiler

可以反编译python1.0-python3.4的编译代码。这个项目是基于Uncompyle2和Decompyle ++。这是一个exe项目文件。

反编译完成后会在目录下生成一个后缀为dis的文件。

地址：https://sourceforge.net/projects/easypythondecompiler/

#### 在线反编译

http://tools.bugscaner.com/decompyle/

### PY文件代码加密

python是一门解释型语言，所以发布项目的时候等于发布了原代码，并不像C语言一样，只需要发布一个编译好的文件即可。那现有的可以一定程度防止代码泄露的方案：

1.  发行 .pyc 文件
2.  使用 oxyry 进行混淆
3.  使用 py2exe
4.  使用cython编译为.c文件，再把.c文件编译为.so 或者pyd的动态链接库文件。

关于加密方式：https://zhuanlan.zhihu.com/p/54296517

这里就提一下其中的第四项，编译为可执行文件，从而加密相关的核心代码。仍然使用上面的python代码，做一点修改，使用cython处理文件。

先准备一个setup.py文件。

```
from distutils.core import setup
from Cython.Build import cythonize
import os

'''
该文件的执行需要的在Terminal中输入   python setup.py build_ext --inplace
使用Cpython 编译python文件，关键函数编译成pyd文件（相当于dll）
'''
# 针对多文件情况设置，单文件就只写一个就行
key_funs = ["pyc.py"]

setup(
    name="pyc",
    ext_modules=cythonize(key_funs),
)
```

运行`python setup.py build_ext –inplace`。会在目录下生成一个pyd动态链接库文件。如下方式调用即可。

```
>>> from pyc import secend
>>> secend()
```



