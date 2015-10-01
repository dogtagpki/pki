from setuptools import find_packages, setup

REQUIRES = [
        'python-ldap',
        'paramiko',
        'requests',
        'PyYAML',
        'pytest_multihost',
        'pytest'
        ]

with open('README.rst', 'r') as f:
    README = f.read()

setup(
        name = 'pkilib',
        version = '0.1',
        description = u'Dogtag & Red Hat Certificate system python test suite',
        long_description = README,
        author = u'CS QE Team',
        url = 'http://git.app.eng.bos.redhat.com/git/pki-tests.git/',
        packages = find_packages(exclude=['tests*']),
        package_data={'':['LICENSE']},
        include_package_data=True,
        install_requires=REQUIRES,
        license='GNU GPL v3.0',
        classifiers=(
            'Programming Language :: Python',
            'Programming Language :: Python :: 2.7',
            ),
        )




