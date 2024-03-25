import os
import re
from setuptools import find_packages, setup

# Based on https://github.com/mitmproxy/mitmproxy/blob/main/setup.py

here = os.path.abspath(os.path.dirname(__file__))

# get version
with open(os.path.join(here, "pwnpatch", "main.py")) as f:
    match = re.search(r'VERSION = "(.+?)"', f.read())
    if not match:
        raise Exception("Can't find version string")
    VERSION = match.group(1)

# get requirements
with open(os.path.join(here, "requirements.txt")) as f:
    req = []
    for r in f.read().strip().split("\n"):
        if not r.startswith('#'):
            req.append(r)

setup(
    name="pwnpatch",
    version=VERSION,
    description="pwnpatch: ctf pwn patch tool",
    packages=find_packages(
        include=["pwnpatch", "pwnpatch.*"]
    ),
    include_package_data=True,
    python_requires=">=3.6",
    install_requires=req
)