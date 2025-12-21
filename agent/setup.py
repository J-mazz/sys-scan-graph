#!/usr/bin/env python3
#    .________      ._____.___ .______  .______ .______ .___ .______  .___
#    :____.   \     :         |:      \ \____  |\____  |: __|:      \ : __|
#     __|  :/ |     |   \  /  ||   .   |/  ____|/  ____|| : ||       || : |
#    |     :  |     |   |\/   ||   :   |\      |\      ||   ||   |   ||   |
#     \__. __/      |___| |   ||___|   | \__:__| \__:__||   ||___|   ||   |
#        :/               |___|    |___|    :       :   |___|    |___||___|
#        :                                  •       •                 
#                                                                          
#
#    2925
#    setup.py

# ==============================================================================
"""
sys-scan-graph-agent Package Setup

Setup configuration for the Python intelligence layer package that provides
AI-powered analysis and enrichment of security scan results.
"""

from setuptools import setup, find_packages
import os

# Read the contents of your README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='sys-scan-agent',
    version='5.0.3',  # Increment this for every new version you publish
    author='Joseph Mazzini',
    author_email='joseph@mazzlabs.works',
    description='AI-powered intelligence layer for the sys-scan-graph security scanner.',
    long_description=long_description,
    long_description_content_type="text/markdown",
    url='https://github.com/J-mazz/sys-scan-graph',
    license='Apache License 2.0',
    # Let setuptools find all packages automatically
    packages=find_packages(),
    # Include non-python files specified in MANIFEST.in
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
    python_requires='>=3.8',
    # Core dependencies only - keep it lightweight
    install_requires=[
        'pydantic>=2.7,<3',
        'sqlalchemy>=2.0,<3',
        'typer>=0.12,<0.13',
        'rich>=13.0,<14',
        'click>=8.1.0,<8.2.0',
        'pyyaml>=6.0,<7',
        'orjson>=3.9,<4',
        'jsonschema>=4.21,<5',
        'PyNaCl>=1.5,<2',
    ],
    # Optional dependencies for AI/ML features and development
    extras_require={
        'ai': [
            'langgraph>=0.2,<1',
            'langchain-core>=0.3,<1',
            'torch>=2.0.0',
            'transformers>=4.40.0',
            'peft>=0.10.0',
            'accelerate>=0.29.0',
            'safetensors>=0.4.0',
            'huggingface_hub>=0.20.0',
        ],
        'api': [
            'langchain>=0.3,<1',
            'langchain-core>=0.3,<1',
            'langchain-openai>=0.2,<1',
            'langchain-anthropic>=0.2,<1',
        ],
        'dev': [
            'pytest>=8.0,<9',
            'pytest-asyncio>=0.23,<0.24',
        ],
    },
    # This creates the `sys-scan-graph` command
    entry_points={
        'console_scripts': [
            'sys-scan-graph=sys_scan_agent.cli:app',
            'sys-scan-intelligence=sys_scan_agent.cli:app'
        ],
    },
)