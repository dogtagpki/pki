Conftest
========
This doc describes pytest conftest file used to configure fixtures for using pytest-multihost plugin

Introduction
-------------
conftest.py allows to put all the fixtures required for a test suite be placed in a file , which can be
referenced from all the tests in that directory. 

Session scoped Multihost Fixture
---------------------------------
This function defines the session_multihost session fixture that defines
the config for the multihost object.  This includes the hosts needed for
the test.  This will need to change depending on how many hosts are
needed for which roles.

- Example::

    @pytest.fixture(scope="session")
    def session_multihost(request):
        """ Mulithost plugin fixture for session scope """
        mh = make_multihost_fixture(
            request,
            descriptions=[
                {
                    'type': 'pki',
                    'hosts': {
                        'master': 1,
                        'clone': 1,
                    },
                },
            ],
            config_class=qe_class.QeConfig
        )
        mh.domain = mh.config.domains[0]
        [mh.master] = mh.domain.hosts_by_role('master')
        [mh.replica] = mh.domain.hosts_by_role('clone')
        return mh

- Change hosts dictionary to match what is needed for the test suite.

- If test suite needs only 1 master, change to::

                    'hosts': {
                        'master': 1,
                    },

- If test suite needs 1 master and 4 clients, change to::

                    'hosts': {
                        'master': 1,
                        'client': 4,
                    },

Class Scoped Multihost Fixture
------------------------------

This function defines the multihost class fixture that will be used
by the majority of tests.  This defines the class level setup and 
teardown method names as class_setup and class teardown respectively.

- Example::

    @pytest.fixture(scope='class')
    def multihost(session_multihost, request):
        """ multihost plugin fixture for class scope """
        if hasattr(request.cls(), 'class_setup'):
            request.cls().class_setup(session_multihost)
            request.addfinalizer(lambda: request.cls().class_teardown(session_multihost))
        return session_multihost

- This should not normally require any changes.

Session Scoped Setup and Teardown Fixtures
------------------------------------------

This function defines the fixture that sets up the setup and teardown
at the session scope.  This is done by running a TestPrep class method
for each function provided later in this file.

- Example::

    @pytest.fixture(scope="session", autouse=True)
    def setup_session(request, session_multihost):
        """ define fixture for session level setup """
        tp = TestPrep(session_multihost)
        tp.setup()

        def teardown_session():
            """ define fixture for session level teardown """
            tp.teardown()
        request.addfinalizer(teardown_session)

- This should not normally require any changes.

- This is needed for test suites that have setup/teardown needs by test
  cases where cases are defined as separate modules.

TestPrep Session Scoped Setup and Teardown Class
------------------------------------------------

This class provides the setup and teardown methods for the whole test
suite.  This is needed by test suites that separate cases into separate
modules but, require common setup/teardown steps.  This would be used 
to add Certificate Services  env setup calls for a test suite if not defined in the test
suite itself.

- Example::

    class TestPrep(object):
        """ Session level setup/teardown class """
        def __init__(self, multihost):

            self.multihost = multihost

        def setup(self):
            """
            Session level setup.
            - Add code here that you want run before all modules in test suite.
            - This should be teardown/cleanup code only, not test code.
            """
            pass

        def teardown(self):
            """
            Session level teardown
            - Add code here that you want run after all modules in test suite.
            - This should be teardown/cleanup code only, not test code.
            """
            pass


- Use case would be to have setup create directories::

    class TestPrep(object):
            """ Session level setup/teardown class """
    def __init__(self, multihost):

        self.multihost = multihost

    def setup(self):
        """
        Session level setup.
        - Add code here that you want run before all modules in test suite.
        - This should be teardown/cleanup code only, not test code.
        """
        self.multihost.master.run_command(['mkdir', '/root/multihost_tests'])
        self.multihost.clone.run_command(['mkdir', '/root/multihost_tests'])

    def teardown(self):
        self.multihost.master.run_command(['rmdir', '/root/multihost_tests'])
        self.multihost.clone.run_command(['rmdir', '/root/multihost_tests'])


- This is useful for normal test suites to setup env.  It is run by pytest
  for any level of test execution--test suite, sub-suite, or test case.

- This could also pre-create users/groups/hosts/etc used by any/all test 
  cases if there are multiple sub-suite test modules.
