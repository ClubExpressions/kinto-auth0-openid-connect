import setuptools

setuptools.setup(
    name="kinto-auth0-openid-connect",
    version="0.1.0",
    url="https://github.com/ClubExpressions/kinto-auth0-openid-connect",

    author="Damien Lecan",
    author_email="dev@dlecan.com",

    description="Auth0 Authentication support for Kinto with OpenId Connect flow",
    long_description=open('README.md').read(),

    packages=setuptools.find_packages(),

    install_requires=[],

    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
)
