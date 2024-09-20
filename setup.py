"""
Setup configuration for the libcovulor package.
"""

from setuptools import setup, find_packages

with open('README.md', 'r', encoding='utf-8') as fh:
    long_description = fh.read()

setup(
    name='libcovulor',
    version='1.4.0.0',
    packages=find_packages(),
    install_requires=[
        'motor==3.5.1',
        'openai==1.46.0',
        'pymongo==4.6.3',
        'pydantic==2.6.4',
        'pydantic_core==2.16.3',
        'pytest-asyncio',
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
