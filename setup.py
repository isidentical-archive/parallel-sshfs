from setuptools import setup

setup(
    name="parallel-sshfs",
    version="2021.05.28a0",
    py_modules=["parallel_sshfs"],
    install_requires=["parallel-ssh==2.5.4"],
)
