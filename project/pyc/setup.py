from distutils.core import setup
from Cython.Build import cythonize
import os

key_funs = ["pyc.py"]

setup(
    name="pyc",
    ext_modules=cythonize(key_funs),
)
