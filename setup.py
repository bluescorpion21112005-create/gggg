from setuptools import setup, find_packages

setup(
    name="cybrix_ai",
    version="0.1.0",
    packages=find_packages(),
    # qasync's event loop never runs tasks on Python 3.14 (Qt timers fail), so the GUI hangs.
    python_requires=">=3.10,<3.14",
    install_requires=[
        # dependencies are in requirements.txt
    ],
    entry_points={
        "console_scripts": [
            "cybrix-ai=main:main",
        ],
    },
)