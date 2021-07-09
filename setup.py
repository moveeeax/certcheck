import os

from setuptools import find_packages, setup

here = os.path.abspath(os.path.dirname(__file__))


def read_long_description():
    path = os.path.join(here, "README.md")
    if os.path.exists(path):
        with open(path, "r") as handle:
            return handle.read()
    return ""


setup(
    name="certcheck",
    version="0.1.0",
    description="TLS certificate expiry and info checker",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    author="Michael Tarassov",
    author_email="michael@tarassov.me",
    license="MIT",
    url="https://github.com/moveeeax/certcheck",
    packages=find_packages(exclude=("tests", "tests.*")),
    python_requires=">=3.6",
    entry_points={
        "console_scripts": [
            "certcheck=certcheck.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
)
