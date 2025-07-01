#!/usr/bin/env python3
"""Setup script for tor-network-model package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="tor-network-model",
    version="0.1.0",
    author="Masic",
    description="A research toolkit for modeling timing analysis attacks on Tor networks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/GH05TCREW/tor-network-model",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov",
            "black",
            "flake8",
            "mypy",
        ],
        "notebooks": [
            "jupyter",
            "ipywidgets",
        ],
    },
    entry_points={
        "console_scripts": [
            "tor-sim=tor_sim.cli:main",
        ],
    },
)
