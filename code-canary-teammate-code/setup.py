"""
Setup script for Code Canary.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    requirements = [
        line.strip() 
        for line in requirements_path.read_text().splitlines() 
        if line.strip() and not line.startswith("#")
    ]

setup(
    name="dependency-canary",
    version="0.1.0",
    author="Code Canary Team",
    author_email="team@code-canary.com",
    description="Minimal SBOM generator and vulnerability enrichment (OSV, NVD, GHSA) with optional Modal parallelization",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/code-canary",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.9",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "pytest-mock>=3.11.0",
            "black>=23.0.0",
            "isort>=5.12.0",
            "flake8>=6.0.0",
            "mypy>=1.5.0",
        ],
        "web": [
            "fastapi>=0.104.0",
            "uvicorn>=0.24.0",
            "jinja2>=3.1.0",
            "plotly>=5.17.0",
            "dash>=2.14.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "dependency-canary=dependency_canary.cli:cli",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=[
        "security", "sbom", "vulnerabilities", "dependencies",
        "supply-chain", "modal", "scanning"
    ],
)
