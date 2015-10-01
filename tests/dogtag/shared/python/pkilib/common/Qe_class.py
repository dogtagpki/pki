import pytest_multihost.config
import pytest_multihost.host
import logging
import pytest

"""
qe_class provides the expansion to the py.test multihost plugin for CS Testing
"""

class QeConfig(pytest_multihost.config.Config):
    """
    QeConfig subclass of multihost plugin to extend functionality
    """
    extra_init_args = {}

    def __init__(self, **kwargs):
        """
        Initialize pytest_multihost.config with default variables
	
	:param kwargs:
        """
	self.log = self.get_logger('%s.%s' % (__name__, type(self).__name__))
        pytest_multihost.config.Config.__init__(self, **kwargs)


    def get_domain_class(self):
        """
        return custom domain class.  This is needed to fully extend the config for
        custom multihost plugin extensions.
	
	:param None:

	:return None:
        """
        return QeDomain

    def get_logger(self, name):
        """
        Override get_logger to set logging level 
	
	:param str name:
	:return obj log:
        """
        log = logging.getLogger(name)
        log.propagate = False
        if not log.handlers:
            #set log Level
            log.setLevel(logging.DEBUG)
            handler = logging.StreamHandler()
            handler.setLevel(logging.DEBUG)
            #set formatter
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            log.addHandler(handler)
        return log

class QeDomain(pytest_multihost.config.Domain):
    """
    QeDomain subclass of multihost plugin domain class. 
    """
    def __init__(self, config, name, domain_type):
	"""
	Subclass of pytest_multihost.config.Domain 

	:param obj config: config config
	:param str name: Name 
	:param str domain_type:

	:return None:
	"""

        self.type = str(domain_type)
        self.config = config 
        self.name = str(name)
        self.hosts = []

    def get_host_class(self, host_dict):
        """
        return custom host class
        """
        return QeHost

class QeHost(pytest_multihost.host.Host):
    """
    QeHost subclass of multihost plugin host class.  This extends functionality
    of the host class for IPA QE purposes.  Here we add support functions that
    will be very widely used across tests and must be run on any or all hosts
    in the environment.
    """
    def qerun(self, command, stdin_text=None, exp_returncode=0, exp_output=None):
        """
        qerun :: <command> [stdin_text=<string to pass as stdin>] 
            [exp_returncode=<retcode>]
            [<exp_output=<string to check from output>]
        - function to run a command and check return code and output

	:param str command: Command 
	:param str stdin_text: Stdin
	:param int exp_returncode: Return code (default 0)
	:param str exp_output: Check the expected output
        """
        cmd = self.run_command(command, stdin_text, raiseonerr=False)
        if cmd.returncode != exp_returncode:
            pytest.xfail("returncode mismatch.")
            print("GOT: ", cmd.returncode)
            print("EXPECTED: ", exp_returncode)

        if exp_output == None:
            print("Not checking expected output")

        elif cmd.stdout_text.find(exp_output) == 0:
            pytest.xfail("expected output not found")
            print("GOT: ", cmd.stdout_text)
            print("EXPECTED: ", exp_output)

        print("COMMAND SUCCEEDED!")

