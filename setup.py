from setuptools import setup, find_packages

setup(
    name='collabpoller',
    version='0.2',
    description='Poll a private Burp Collaborator server without needing Burp Professional',
    author='aringo',
    packages=find_packages(),
    install_requires=[
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'collabpoller=collabpoller.poller:main',
        ],
    },
)
