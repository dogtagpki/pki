from setuptools import setup


setup(
    # A hyphen ('-') gets converted to underscore ('_') while packaging
    # so avoiding the name pki-healthcheck
    name='pkihealthcheck',
    version='0.1',
    packages=[
        'pki.server.healthcheck.core',
        'pki.server.healthcheck.meta',
    ],
    entry_points={
        # creates bin/pki-healthcheck
        'console_scripts': [
            'pki-healthcheck = pki.server.healthcheck.core.main:main'
        ],
        # register the plugin with ipa-healthcheck
        'ipahealthcheck.registry': [
            'pkihealthcheck.pki = pki.server.healthcheck.meta.plugin:registry',
        ],
        # register the plugin with pki-healthcheck
        'pkihealthcheck.registry': [
            'pkihealthcheck.pki = pki.server.healthcheck.meta.plugin:registry',
        ],
        # plugin modules for pkihealthcheck.pki registry
        'pkihealthcheck.pki': [
            'pki_certs = pki.server.healthcheck.meta.csconfig',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3.6',
    ],
    python_requires='!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*',
    setup_requires=['pytest-runner',],
    tests_require=['pytest',],
)
