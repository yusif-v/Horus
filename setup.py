from setuptools import setup, find_namespace_packages

setup(
    name="horus",
    version="0.7.0",
    packages=find_namespace_packages(include=["horus", "horus.*"]),
    python_requires=">=3.10",
    extras_require={
        "web": ["flask>=3.0"],
    },
    entry_points={
        "console_scripts": [
            "horus=horus.cli:main",
        ],
    },
)
