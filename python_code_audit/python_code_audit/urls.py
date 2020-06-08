"""python_code_audit URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
import code_audit.views

from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path('admin/', admin.site.urls),
    path('xss/', code_audit.views.XSS),
    path('sql/', code_audit.views.SQLi),
    path('csrf/', code_audit.views.CSRF),
    path('ssrf/', code_audit.views.SSRF),
    path('cmd/', code_audit.views.COMMAND),
    path('readfile/', code_audit.views.READFILE),
    # path('upload/', code_audit.views.IndexView.as_view()),
    path('upload/', code_audit.views.UPLOADFILE),
    path('ssti/', code_audit.views.SSTI),
    path('infor/', code_audit.views.INFOR),
    path('bypass/', code_audit.views.BYPASS),
]+static(settings.MEDIA_URL,document_root = settings.MEDIA_ROOT)

