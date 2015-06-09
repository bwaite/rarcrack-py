from os.path import join
from setuptools import setup, find_packages

setup(
    name = 'rarcrack-py',
    url='http://github.com/bwaite/rarcrack-py/',
    license='MIT',
    version = '0.3',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'rarcrack-py=rarcrack.rarcrack:main',
        ],
    },
    )
