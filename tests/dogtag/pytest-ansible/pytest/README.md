# Pytest-ansible for Dogtag Tests

## Note
Recommended version to install ansible version 2.3.x. 
Integration testing with other versions like pytest-ansible 2.4.0  are still in-progress.

## Installing pip

[pip] (https://pip.pypa.io/en/stable/installing/)  is needed for ansible & pytest installation.

## Description about pytest-ansible & pytest-ansible-playbook

This repository contains a plugin for py.test which adds several fixtures for running ansible modules, or inspecting ansible_facts. While one can simply call out to ansible using the subprocess module, having to parse stdout to determine the outcome of the operation is unpleasant and prone to error. With pytest-ansible, modules return JSON data which you can inspect and act on, much like with an ansible playbook.
See [pytest-ansible] (https://pypi.python.org/pypi/pytest-ansible)

### Installation

#### Installing ansible
#### Installing pytest-ansible
#### Installing pytest-ansible-playbook

Covered under [README] (../README.md#installing-supporting-packages)
### Usage

Once installed, the following py.test command-line parameters are available:

```
     py.test \
    [--ansible-inventory <path_to_inventory>] \
    [--ansible-host-pattern <host-pattern>] \
    [--ansible-playbook-directory <path_to_directory_with_playbooks>] \
    [--ansible-playbook-inventory <path_to_inventory_file>]
    [--ansible-connection <plugin>] \
    [--ansible-user <username>] \
    [--ansible-sudo] \
    [--ansible-sudo-user <username>]

```

#### Mandatory command-line parameters:

```
    py.test \
    [--ansible-inventory <path_to_inventory>] \
    [--ansible-playbook-directory <path_to_directory_with_playbooks>] \
    [--ansible-playbook-inventory <path_to_inventory_file>] \
    [--ansible-host-pattern <host-pattern>]
```

### Available Fixtures with pytest-ansible

1. Fixture ansible_module

    The ansible_module fixture allows tests and fixtures to call ansible modules. See [ansible_module] (http://docs.ansible.com/ansible/2.3/modules.html)

2. Fixture ansible_facts

    The ansible_facts fixture returns a JSON structure representing the system facts for the associated inventory. Sample fact data is available in the [ansible documentation](http://docs.ansible.com/ansible/latest/playbooks_variables.html#information-discovered-from-systems-facts)

### Available Fixtures with pytest-ansible-playbook

1. Fixture ansible playbook

    The plugin provides a single pytest fixture called ansible_playbook. To specify playbooks to be executed by the fixture, use the following pytest markers:

```

    @pytest.mark.ansible_playbook_setup('playbook.yml')
    @pytest.mark.ansible_playbook_teardown('playbook.yml')

    @pytest.mark.ansible_playbook_setup('playbook.01.yml', 'playbook.02.yml')

```

### Install pytest-autochecklog

In case you have plans to use logging that we get from `pytest-autochecklog`, get it using

```
pip install pytest-autochecklog
```

###  Parameterizing with pytest.mark.ansible

Perhaps the --ansible-inventory=<inventory> includes many systems, but you only wish to interact with a subset. The pytest.mark.ansible marker can be used to modify the pytest-ansible command-line parameters for a single test.

For example, to interact with the local system, you would adjust the host_pattern and connection parameters.


```
@pytest.mark.ansible(host_pattern='local,', connection='local')
class Test_Local(object):
    def test_install(self, ansible_module):
        '''do some testing'''
    def test_template(self, ansible_module):
        '''do some testing'''
    def test_service(self, ansible_module):
        '''do some testing'''
```
It works with both class and function.

More on [Paramaterizing](https://docs.pytest.org/en/latest/example/parametrize.html)

### Exception Handling

Below is the example of exception handling.During runtime, if we wanted to change inventory file it can be done using `@pytest.mark.ansible(inventory='abc')`.
Here , if host mentioned in file "abc" is not reachable using ping it should raise exception `AnsibleHostUnreachable`

```
@pytest.mark.ansible(inventory='abc')
def test_shutdown(ansible_module):
         pytest.raises(pytest_ansible.plugin.AnsibleHostUnreachable, ansible_module.ping)
```

## About PKI Module

PKI module is an ansible module that can be called either from python code or from ansible-playbooks to run any pki client commands
See [PKI Module](https://copr.fedorainfracloud.org/coprs/gkapoor1/idm-modules) for latest modules and common packages.

PKI Module has few default values and those can be over-written by defining them during tests creation.This is same as any standard ansible modules.

### Getting PKI Module

PKI module can be installed with below procedure. Install latest rpm from [copr site] (https://copr.fedorainfracloud.org/coprs/gkapoor1/idm-modules/package/idm-modules/)

```
Example: 

1. wget https://copr-be.cloud.fedoraproject.org/results/gkapoor1/idm-modules/epel-7-x86_64/00656258-idm-modules/idm-modules-0.1-34.g0417811.noarch.rpm
2. rpm -qlp idm-modules-0.1-34.g0417811.noarch.rpm
    - Make sure above command lists pki.py module
3. rpm -ivh idm-modules-0.1-34.g0417811.noarch.rpm

Make sure pki.py exist under PYTHONPATH/ansible/modules/identity/pki/pki.py
```

In case, it is difficult with above procedure, this can be done manually using

```
cp pki-pytest-ansible/raw/pytest-task/common-modules/pki.py PYTHONPATH/ansible/modules/identity/pki/pki.py
```

All the common modules are part of common-modules code.

### Usage

`with python`

```
def test_pki(ansible_facts,ansible_module):
    for (host, facts) in ansible_facts.items():
    	contacted = ansible_module.pki(
        cli='ca-cert-find',
		hostname = host,
		nssdb = '/root/nssdb',
		certnick = "'PKI Administrator for example.com'"
    	)
    item=contacted.items()
    print dict(item)

For Positive test case:
----------------------

@pytest.mark.positive
def test_tpsToken_show_01(ansible_module, certnick, expected):
    contacted = ansible_module.pki(
                cli='ca-cert-find',
                protocol='http',
                certnick = certnick
        )
    for  result in contacted.values():
        for iter in expected:
                assert iter in result['stdout']

For Negative test case:
-----------------------

@pytest.mark.negative
def test_tpsToken_show_01(ansible_module, certnick, expected):
    contacted = ansible_module.pki(
                cli='ca-cert-find',
                protocol='http',
                certnick = certnick
        )
    for  result in contacted.values():
        for iter in expected:
                assert iter in result['stderr']


```

`with ansible-playbook`

```
  tasks:

    - name: Run pki module from ansible-playbook
      pki: cli='ca-cert-show' port='9443'

Output

"cmd": "pki -d /opt/rhqa_pki/certdb -P http -p 9443 -h localhost -c Secret123 -n 'PKI CA Administrator for Example.Org' ca-cert-show "

```
### Examples

See [Examples](tps-token/test_tps_token_show.py)

### Parametrizing your tests

This involves clubbing of tests which are similar in nature.

Example: All Positive tests whose output comes under stdout can be clubbed together.

Negative tests where output goes in stderr can be put together.

See [Parametrizing your tests](tps-token/test_tps_token_show.py)

### Advantages of parametrizing tests

1. Test cases are much shorter.
2. Easy to run smoke, positive, negative cases using markers.
3. Similar kind of test are clubbed together and avoid code duplication.
4. Multiple asserts are implemented.
5. Code is never touched.Just input and output is changed.

## Pre-requisite before running a pytest-ansible using pki module

Py.test assumes that your Subsystem installation is done using [ansible-playbooks](../installation/README.md)
Tests look for ansible environment constants file for fetching port if not provided in pytest code.


## Importing the CA cert to nssdb. Please run this command on the machine on which RHCS is setup

```
1. Create nssdb in /opt/rhqa_pki/certdb.
2. Import CA Admin Certificate into nssdb.
pki -d /opt/rhqa_pki/certdb/ -c Secret123 -h <hostname> -p <CA HTTP PORT> client-cert-import "RootCA" --ca-server
pk12util -i <Subsystem admin p12 file> -d /opt/rhqa_pki/certdb -K Secret123 -W Secret123
```

## Running a pytest-ansible test

```
py.test --ansible-inventory host --ansible-host-pattern master <python file>  -q -s  -vvv
```

where,

    --ansible-inventory,   the inventory file from where hosts ip are picked.
    --ansible-host-pattern,  the host pattern on which tests needs to be run like master or clone


## Running a combination of pytest-ansible and pytest-ansible-playbook

```
py.test --ansible-inventory host --ansible-host-pattern master --ansible-playbook-inventory host <python file>  -q -s  -vvv
```


where,

    --ansible-inventory,  the inventory file from where hosts ip are picked.
    --ansible-host-pattern,  the host pattern on which tests needs to be run.
    --ansible-playbook-inventory,  the inventory file used for running playbooks which are defined in form of fixtures to run.

Refer [Available Fixtures with pytest-ansible-playbook](README.md#available-fixtures-with-pytest-ansible-playbook)

## Examples of ansible-inventory and ansible-playbook-inventory

Inventory file consist of the roles and the ip-address.Tests will run for the roles and ip's that are mentioned.

```
[master]
10.1.2.3
10.2.3.4
```

## Troubleshooting Errors

To Debug any error, `Run py.test command with reporting option.`

```
reporting:
  -v, --verbose         increase verbosity.
  -q, --quiet           decrease verbosity.
  -r chars              show extra test summary info as specified by chars
                        (f)ailed, (E)error, (s)skipped, (x)failed, (X)passed,
                        (p)passed, (P)passed with output, (a)all except pP.
                        The pytest warnings are displayed at all times except
                        when --disable-pytest-warnings is set
  --disable-pytest-warnings
                        disable warnings summary, overrides -r w flag
  -l, --showlocals      show locals in tracebacks (disabled by default).
  --tb=style            traceback print mode (auto/long/short/line/native/no).
  --full-trace          don't cut any tracebacks (default is to cut).
  --color=color         color terminal output (yes/no/auto).
  --durations=N         show N slowest setup/test durations (N=0 for all).
  --pastebin=mode       send failed|all info to bpaste.net pastebin service.
  --junit-xml=path      create junit-xml style report file at given path.
  --junit-prefix=str    prepend prefix to classnames in junit-xml output
  --result-log=path     DEPRECATED path for machine-readable result log.
  --excel-report=path   create excel report file at given path.
```

## Additional Packages

These are additional logging packages that could be used in future if logging improvement is needed.

- [Logging-1](https://pypi.python.org/pypi/pytest-logger).
- [Logging-2](ttps://pypi.python.org/pypi/pytest-autochecklog).


