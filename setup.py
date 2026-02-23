from setuptools import setup, find_packages

setup(
    name="zt-ai-proxy-core",
    version="0.1.0",
    description="ZeroTrusted AI Proxy Core - MITM interception, PII detection, and enforcement logic (standalone edition)",
    author="ZeroTrusted.ai",
    author_email="opensource@zerotrusted.ai",
    url="https://github.com/zerotrusted-ai/zt-ai-proxy",
    packages=find_packages(include=["interceptor*", "standalone*"]),
    include_package_data=True,
    install_requires=[
        "mitmproxy>=9.0.0",
    ],
    python_requires=">=3.8",
    license="MIT",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
)