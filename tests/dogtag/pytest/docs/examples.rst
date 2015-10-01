Examples of using Multihost Plugin with Fixture for certificate Services
========================================================================
pytest multihost plugin uses paramiko/OpenSSHTransport to connect to hosts and provides methods
to run commands and copy files. 


Examples
--------
* Run command remotely::

        import pytest

        @pytest.fixture(scope='session')
        def session_multihost(request):
            mh = make_multihost_fixture(
            request,
            descriptions =
            [   
                {   
                    'type': 'cs',
                    'hosts':
                    {   
                        'master': 1,
                        'clone' : 1
                    }
                },
            ],
            config_class=QeConfig)
            mh.domain = mh.config.domains[0]
            [mh.master] = mh.domain.hosts_by_role('master')
            [mh.clone] = mh.domain.hosts_by_role('clone')
            return mh

        class TestCase:
            def test1(multihost):
                multihost.master.run_command(['ls', '-l'])


* Copy files remotely::
        
        class TestCase:
             def test1(multihost):
                 #copy ca configuration file to master 
                 multihost.master.transport.put_file(CAFile, '/tmp/ca_cfg')
        
* Run a command and check results::
        
        class Testcase:
             def test1(multihost):
                multihost.master.qerun(['pkispawn', '-s', 'CA', '-f', '/tmp/ca_cfg', '-vv'], exp_returncode=0, exp_output=expected_out)

        
