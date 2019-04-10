#!/usr/bin/env python3

from setuptools import setup, find_packages
from os import path


def read(fname):
    return open(path.join(path.dirname(__file__), fname)).read()


setup(
    name='pymetasploit3',
    author='Dan McInerney',
    version='3.0',
    author_email='danhmcinerney@gmail.com',
    description='A full-fledged msfrpc library for Metasploit framework.',
    license='GPL',
    packages=find_packages('pymetasploit3'),
    package_dir={ '' : 'pymetasploit3' },
    scripts=[
        'pymetasploit3/scripts/pymsfconsole',
        'pymetasploit3/scripts/pymsfrpc'
    ],
    install_requires=[
        'msgpack',
        'requests'
    ],
    url='https://github.com/DanMcInerney/pymetasploit3',
    download_url='https://github.com/DanMcInerney/pymetasploit3/zipball/master',
    long_description=read('README')
)
