from setuptools import setup


setup(
    # A hyphen ('-') gets converted to underscore ('_') while packaging
    # so avoiding the name pki-healthcheck
    name='pkihealthcheck',
    version='0.1',
    packages=[
        'pki.server.healthcheck.core',
        'pki.server.healthcheck.meta',
        'pki.server.healthcheck.certs'
    ],
    entry_points={
        # creates bin/pki-healthcheck
        'console_scripts': [
            'pki-healthcheck = pki.server.healthcheck.core.main:main'
        ],
        # register the plugin with ipa-healthcheck
        'ipahealthcheck.registry': [
            'pkihealthcheck.meta = pki.server.healthcheck.meta.plugin:registry',
            'pkihealthcheck.certs = pki.server.healthcheck.certs.plugin:registry',
        ],
        # register the plugin with pki-healthcheck
        'pkihealthcheck.registry': [
            'pkihealthcheck.meta = pki.server.healthcheck.meta.plugin:registry',
            'pkihealthcheck.certs = pki.server.healthcheck.certs.plugin:registry',
        ],
        # plugin modules for pkihealthcheck.meta registry
        'pkihealthcheck.meta': [
            'pki_certs = pki.server.healthcheck.meta.csconfig',
            'pki_connectivity = pki.server.healthcheck.meta.connectivity'
        ],
        # plugin modules for pkihealthcheck.certs registry
        'pkihealthcheck.certs': [
            'trust_flags = pki.server.healthcheck.certs.trustflags',
            'expiration = pki.server.healthcheck.certs.expiration',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3.6',
    ],
    python_requires='!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*,!=3.4.*',
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
)
