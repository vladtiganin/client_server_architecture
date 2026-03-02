import pybind11
from setuptools import setup, Extension


vcpkg_root = r'C:\\Users\\User\\vcpkg'  # например, C:\Users\User\vcpkg

ext_modules = [
    Extension(
        'rsa_core',
        ['py_wrapper.cpp', 'RSA.cpp', 'MillerRabenTest.cpp'],
        include_dirs=[
            pybind11.get_include(),
            f'{vcpkg_root}\\installed\\x64-windows\\include',
        ],
        library_dirs=[
            f'{vcpkg_root}\\installed\\x64-windows\\lib',
        ],
        libraries=['gmp', 'gmpxx'],  # Линкуем обе для поддержки C++
        language='c++',
        extra_compile_args=['/std:c++11', '/EHsc'],  # Флаги MSVC
    ),
]

setup(
    name='rsa_core',
    version='1.0.0',
    author='vlad',
    author_email='vladtiganin27@gmail.com',
    description='RSA',
    ext_modules=ext_modules,
    requires=['pybind11'],
)