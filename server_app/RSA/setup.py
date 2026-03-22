import pybind11
from setuptools import setup, Extension


ext_modules = [
    Extension(
        'rsa_core',
        ['py_wrapper.cpp', 'RSA.cpp', 'MillerRabenTest.cpp'],
        include_dirs=[
            pybind11.get_include(),
        ],
        libraries=['gmp', 'gmpxx'], 
        language='c++',
        extra_compile_args=["-std=c++17"],  
    ),
]

setup(
    name='server_app_rsa_core',
    version='1.0.0',
    author='vlad',
    author_email='vladtiganin27@gmail.com',
    description='RSA',
    ext_modules=ext_modules,
    requires=['pybind11'],
)