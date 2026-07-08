from setuptools import setup, find_packages

setup(
    name="cybrix_ai",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        # dependencies are in requirements.txt
    ],
    entry_points={
        "console_scripts": [
            "cybrix-ai=main:main",
        ],
    },
)