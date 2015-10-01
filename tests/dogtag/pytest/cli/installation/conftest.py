from pytest_multihost import make_multihost_fixture
from pkilib.common.mh_wrapper import W_DirSrv
from pkilib.common.Qe_class import QeConfig
import pytest
import tempfile
import os

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

@pytest.fixture(scope="class")
def DSInstance(session_multihost, request):
    master_ds_inst = W_DirSrv(session_multihost.master)
    clone_ds_inst = W_DirSrv(session_multihost.clone)
    return (master_ds_inst, clone_ds_inst)

@pytest.fixture(scope="class")
def multihost(session_multihost, DSInstance, request):
    if hasattr(request.cls(), 'class_setup'):
        request.cls().class_setup(session_multihost, DSInstance)
        request.addfinalizer(lambda: request.cls().class_teardown(session_multihost, DSInstance))
    return session_multihost

@pytest.fixture(scope="class")
def TempFile(request):
    (tmp_cfg_fd, tmp_cfg_file_path) = tempfile.mkstemp()
    os.close(tmp_cfg_fd)
    def Remove_TempFile():
        print("Removing %r" %(tmp_cfg_file_path))
        os.remove(tmp_cfg_file_path)
    request.addfinalizer(Remove_TempFile)
    return tmp_cfg_file_path



@pytest.fixture(scope="session",autouse=True)
def setup_session(request, session_multihost):
    tp = TestPrep(session_multihost)
    tp.setup()
    def teardown_session():
        tp.teardown()
    request.addfinalizer(teardown_session)

class TestPrep(object):
    def __init__(self, multihost):
        self.multihost = multihost

    def setup(self):
        print("\n............Session Setup...............")
        self.multihost.master.run_command(['mkdir', '/root/multihost_tests'])
        self.multihost.clone.run_command(['mkdir', '/root/multihost_tests'])
        self.multihost.master.run_command(['touch', '/root/multihost_tests/env.sh'])
        self.multihost.clone.run_command(['touch', '/root/multihost_tests/env.sh'])

    def teardown(self):
        print("\n............Session Ends.................")
        self.multihost.master.run_command(['rm', '-f', '/root/multihost_tests/env.sh'])
        self.multihost.clone.run_command(['rm',  '-f','/root/multihost_tests/env.sh'])
        self.multihost.master.run_command(['rmdir', '/root/multihost_tests'])
        self.multihost.clone.run_command(['rmdir', '/root/multihost_tests'])
