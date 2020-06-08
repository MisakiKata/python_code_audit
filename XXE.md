## XXE

具体漏洞就不解释了，都多多少少都见过很多种类型的XXE。Python 有三种方法解析 XML，SAX，DOM，以及 ElementTree:

```
#SAX
xml.sax.parse()

#DOM
xml.dom.minidom.parse()
xml.dom.pulldom.parse()

#ElementTree
xml.etree.ElementTree()
```

第三方xml解析库挺多的，libxml2使用C语言开发的xml解析器，lxml就是基于libxml2使用python开发的。而存在xxe的也就是这个库。

先看一下第三方的lxml存在问题的地方

```python
def xxe():
    tree = etree.parse('xml.xml')
    # tree = lxml.objectify.parse('xml.xml')
    return etree.tostring(tree.getroot())
```

从字符串读取

```python
def xxe():
    # tree = etree.parse('xml.xml')
    # tree = lxml.objectify.parse('xml.xml')
    # return etree.tostring(tree.getroot())
    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE title [ <!ELEMENT title ANY >
            <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]>
            <channel>
                <title>&xxe;</title>
                <description>A blog about things</description>
            </channel>"""
    tree = etree.fromstring(xml)
    return etree.tostring(tree)
```

存在问题原因是，XMLparse方法中`resolve_entities`默认设置为`True`，导致可以解析实体。

```
def __init__(self, encoding=None, attribute_defaults=False, dtd_validation=False, load_dtd=False, no_network=True, ns_clean=False, recover=False, schema=None, huge_tree=False, remove_blank_text=False, resolve_entities=True, remove_comments=False, remove_pis=False, strip_cdata=True, collect_ids=True, target=None, compact=True): # real signature unknown; restored from __doc__
    pass
```

下表概述了标准库XML已知的攻击以及各种模块是否容易受到攻击。

| 种类                                                         | sax          | etree        | minidom      | pulldom      | xmlrpc       |
| :----------------------------------------------------------- | :----------- | :----------- | :----------- | :----------- | :----------- |
| billion laughs                                               | **易受攻击** | **易受攻击** | **易受攻击** | **易受攻击** | **易受攻击** |
| quadratic blowup                                             | **易受攻击** | **易受攻击** | **易受攻击** | **易受攻击** | **易受攻击** |
| external entity expansion                                    | 安全 (4)     | 安全 (1)     | 安全 (2)     | 安全 (4)     | 安全 (3)     |
| [DTD](https://en.wikipedia.org/wiki/Document_type_definition) retrieval | 安全 (4)     | 安全         | 安全         | 安全 (4)     | 安全         |
| decompression bomb                                           | 安全         | 安全         | 安全         | 安全         | **易受攻击** |

1.  [`xml.etree.ElementTree`](https://docs.python.org/zh-cn/3.7/library/xml.etree.elementtree.html#module-xml.etree.ElementTree) 不会扩展外部实体并在实体发生时引发 `ParserError`。
2.  [`xml.dom.minidom`](https://docs.python.org/zh-cn/3.7/library/xml.dom.minidom.html#module-xml.dom.minidom) 不会扩展外部实体，只是简单地返回未扩展的实体。
3.  `xmlrpclib` 不扩展外部实体并省略它们。
4.  从 Python 3.7.1 开始，默认情况下不再处理外部通用实体。

以其中一个为例`xml.dom.pulldom`，实例情况启用对外部实体的处理存在XXE问题。

```python
doc = xml.dom.pulldom.parse('xml.xml')
    for event, node in doc:
        doc.expandNode(node)
        nodes = node.toxml()
    return Response(nodes)
```

### Excel解析导致xxe

部分第三方解析excel表的库

```
xlrd
xlwt
xluntils
openpyxl
```

excel表格和word文档，都是基于压缩的ZIP文件格式规范，里面包含了工作簿数据，文档信息，资料数据等。

`openpyxl<=2.3.5`的时候由于内部是使用lxml模块解析，采用的是默认的配置导致会解析外部实体。

### 修复代码

第三方模块`lxml`按照修改设置来改就可以

```python
def xxe():
    tree = etree.parse('xml.xml', etree.XMLParser(resolve_entities=False))
    # tree = lxml.objectify.parse('xml.xml', etree.XMLParser(resolve_entities=False))
    return etree.tostring(tree.getroot())
```

尝试改用`defusedxml` 是一个纯 Python 软件包，它修改了所有标准库 XML 解析器的子类，可以防止任何潜在的恶意操作。 对于解析不受信任的XML数据的任何服务器代码，建议使用此程序包。

https://pypi.org/project/defusedxml/