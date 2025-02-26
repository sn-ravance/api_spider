from setuptools import setup, find_packages

setup(
    name="api_spider",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "httpx",
        "ollama",
        "pytest",
        "pytest-asyncio"
    ]
)