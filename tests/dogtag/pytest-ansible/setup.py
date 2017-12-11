from setuptools import setup

REQUIRES = [
        'lxml',
        'pytest',
        'pytest-ansible'
        ]

setup(
        name = 'pki.testlib',
        version = '0.1',
        description = u'Dogtag PKI python test suite',
        author = u'CS QE Team',
        author_email='cs-qe@redhat.com',
        namespace_packages = ['pki'],
        package_dir={
            'pki.testlib': 'pki/testlib',
        },
        packages = [
            'pki.testlib',
            'pki.testlib.common',
        ],
        install_requires=REQUIRES,
        license='GNU GPL v3.0',
)
