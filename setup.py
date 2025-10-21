from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

setup(
    name="pqsecure-sync",
    version="2.0.0",
    author="PQ Security Research",
    description="Post-Quantum Secure File Synchronization System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/pqsecure-sync",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        "liboqs-python>=0.14.1",
        "cryptography>=41.0.0",
        "aiofiles>=23.2.1",
        "watchdog>=3.0.0",
        "psutil>=5.9.5",
        "pyyaml>=6.0.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.1.0",
        ],
        "benchmark": [
            "matplotlib>=3.7.2",
            "pandas>=2.0.3",
            "numpy>=1.24.3",
            "seaborn>=0.12.2",
        ],
        "docker": [
            "docker>=6.1.3",
        ],
    },
    entry_points={
        "console_scripts": [
            "pqsync=main:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
