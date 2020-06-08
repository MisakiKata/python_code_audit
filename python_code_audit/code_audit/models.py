from django.db import models
from django.contrib.auth.models import User
from datetime import datetime
from django.utils import timezone
from django.core import validators
# Create your models here.




class File(models.Model):
    filename = models.CharField(verbose_name='文件名', max_length=100)
    filedata = models.DateTimeField(verbose_name='创建时间', default=timezone.now)
    filext = models.FileField(upload_to='%Y/%m/%d',validators=[validators.FileExtensionValidator(['jpg','png'],message='必须是图像文件')], default='')

    class Meta:
        verbose_name = '文件'
        verbose_name_plural = '文件'

    def __str__(self):
        return self.filename