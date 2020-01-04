from setuptools import setup, find_packages

setup(
    name='vulnscan-parser',
    version='0.2',
    author='happyc0ding',
    packages=find_packages(),
    description='Parser for vulnscan results, i.e. nessus, testssl, nmap files',
    long_description='Parses result files into python objects',
    #url='https://github.com/happyc0ding/',
    install_requires=[
        'lxml>=4.2.4',
        'pyparsing>=2.2.0',
        'python-libnmap>=0.7.0',
        'pyOpenSSL>=19.0.0',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Programming Language :: Python :: 3',
        'Topic :: Security'
    ],
    keywords='security parser nessus testssl sslyze nmap vulnerability scanner',
)
