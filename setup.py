#!/usr/bin/env python3
"""
Packet Phantom v2.0.0 - Setup Configuration
============================================

Professional-grade OS fingerprinting & network testing framework.

Installation:
    python setup.py install
    
    OR (development mode):
    pip install -e .
    
    Creates 'pp' console script alias globally.

Author: medaminkh-dev (Amine)
License: [Specify license]
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read long description from README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Core dependencies
REQUIRED_PACKAGES = [
    "scapy>=2.4.5",         # Packet crafting (replaces raw socket implementation)
    "jsonschema>=4.0.0",    # Signature database validation
    "requests>=2.28.0",     # HTTP for CDN support (v2.1+)
    "colorama>=0.4.4",      # Cross-platform colored output
]

# Optional development dependencies
EXTRAS_REQUIRE = {
    "dev": [
        "pytest>=7.0.0",    # Testing
        "pytest-cov>=4.0.0", # Coverage reporting
        "black>=22.0.0",    # Code formatting
        "pylint>=2.14.0",   # Linting
        "mypy>=0.950",      # Type checking
    ],
    "docs": [
        "sphinx>=5.0.0",    # Documentation
        "sphinx-rtd-theme>=1.0.0",  # ReadTheDocs theme
    ],
}

setup(
    # Package Information
    name="packet-phantom",
    version="2.0.0",
    author="medaminkh-dev (Amine)",
    author_email="dev@example.com",  # Update with actual email
    url="https://github.com/medaminkh-dev/packet-phantom",
    description="Professional-grade behavioral OS fingerprinting & network testing framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    
    # Project Metadata
    project_urls={
        "Documentation": "https://github.com/medaminkh-dev/packet-phantom#documentation",
        "Source": "https://github.com/medaminkh-dev/packet-phantom",
        "Bug Tracker": "https://github.com/medaminkh-dev/packet-phantom/issues",
        "Discussions": "https://github.com/medaminkh-dev/packet-phantom/discussions",
    },
    
    # Classification
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: [Licence MIT]",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Internet",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    
    # Keywords for searching
    keywords=[
        "network",
        "reconnaissance",
        "fingerprinting",
        "os-detection",
        "packet-crafting",
        "penetration-testing",
        "network-scanning",
        "tcp-ip",
        "behavioral-analysis",
        "scapy",
        "security",
        "research",
    ],
    
    # Package Configuration
    packages=find_packages(exclude=["tests", "docs", "examples"]),
    include_package_data=True,
    
    # Python Version Requirement
    python_requires=">=3.8",
    
    # Dependencies
    install_requires=REQUIRED_PACKAGES,
    extras_require=EXTRAS_REQUIRE,
    
    # Entry Points (Console Scripts)
    entry_points={
        "console_scripts": [
            # Creates 'pp' command globally for easy access
            "pp=packet_phantom.cli:main",
            
            # Additional entry points for specialized functions (future)
            # "pp-os=packet_phantom.core.os_fingerprint:main",
            # "pp-scan=packet_phantom.core.batch_sender:main",
        ],
    },
    
    # Data Files
    package_data={
        "packet_phantom": [
            "config/default_config.json",
        ],
    },
    data_files=[
        # Signature database
        ("signatures/v2", [
            "signatures/v2_schema.json",
        ]),
        # Include all JSON signature files
        ("signatures/v2", [
            f"signatures/v2/{file}"
            for file in [
                "Linux_5.x.json",
                "Windows_10_11.json",
                "macOS.json",
                "FreeBSD_12.json",
                "Cisco_IOS.json",
                "AWS_EC2.json",
                "Android.json",
            ]
        ]),
    ],
    
    # Additional Metadata
    license="[MIT]",
    
    # Zip Safe (False needed for data files)
    zip_safe=False,
)
