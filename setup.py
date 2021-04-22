from setuptools import setup

files = ["scc/*"]

setup(
    name='pwnpatch',
    version='0.1.1',
    description='My patch util: pwnpatch',
    packages=['pwnpatch'],
    package_data={'pwnpatch': files},
    install_requires=[
        'lief',
        'keystone-engine',
        'capstone',
    ],
)
