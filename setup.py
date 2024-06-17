"""
Setup configuration for the libcovulor package.
"""

from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name='libcovulor',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'pymongo==4.6.2',
        'pydantic==2.6.4',
        'pytest==8.2.1',
        'pytest-mock==3.14.0'
    ],
    author='Plexicus',
    author_email='info@plexicus.com',
    description='CRUD in mongo database.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/plexicus/libcovulor',
)
