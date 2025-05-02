#!/usr/bin/env python3
from setuptools import setup, find_packages

setup(
    name="xytop",
    version="1.0.0",
    description="Combined system monitor (processes, disk I/O, and network)",
    author="Your Name",
    author_email="your.email@example.com",
    url="https://example.com/xytop",
    scripts=["xytop.py"],
    entry_points={
        'console_scripts': [
            'xytop=xytop:run',
        ],
    },
    install_requires=[
        "psutil>=5.8.0",
        "scapy>=2.4.5",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console :: Curses",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.6",
)
