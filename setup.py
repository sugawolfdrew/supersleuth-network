"""
Setup configuration for SuperSleuth Network
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="supersleuth-network",
    version="0.1.0",
    author="SuperSleuth Network Team",
    author_email="support@supersleuth.network",
    description="Enterprise-grade WiFi and network diagnostic tool for IT professionals",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/supersleuth/network",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "supersleuth=src.interfaces.cli:main",
        ],
    },
)