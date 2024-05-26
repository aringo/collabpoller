from setuptools import setup, find_packages

setup(
    name='collabpoller',
    version='0.1',
    Summary='Allows for using private collaborator without needing Burp',
    Author='aringo',
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
