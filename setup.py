from setuptools import setup

setup(
    name="CwmpClient",
    version="0.0.1-beta",
    install_requires=[
        'aiohttp'
    ],
    maintainer="Remi BONNET",
    maintainer_email="bonnet@dites.team",
    include=['CwmpClient'],
)