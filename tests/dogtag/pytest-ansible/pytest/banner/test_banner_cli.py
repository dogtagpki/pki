"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI SERVER BANNER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki server banner commands needs to be tested:
#   pki server banner cli
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Bhavik Bhavsar <bbhavsar@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2017 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# Test cases are based on Test Plan.
# https://polarion.engineering.redhat.com/polarion/#/
# project/CERT/wiki/High Level Designs/Common Criteria Banner
##################################################
# pki-server banner testing #
##################################################
# Test case 1: pki-server banner-show help
# Test case 2: pki-server banner-validate help
# Test case 3 : pki-server banner-show <instance>
# negative scenario when banner is not installed
# Test case 4 : pki-server banner-validate <instance>
# negative scenario when banner is not installed
# Test case 3 : pki-server banner-show <instance>
# positive scenario when banner is installed
# Test Case 5: pki-server banner-validate <instance>
# positive scenario when banner is installed
# Test CAse 6: empty banner and check banner show and banner validate
# Test Case 7: modify banner and check banner show and banner validate
# Test Case 8: ignore banner in userpace ~/.dogtag/pki.conf
# Test Case 9: ignore banner in pki cli
# Test Case 10: accept banner in pki cli
# Test Case 11: reject banner in pki cli
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import pytest
import random
import os
if os.path.isfile('/tmp/test_dir/constants.py'):
    import sys
    sys.path.append('/tmp/test_dir')
    import constants


master = pytest.mark.ansible(host_pattern="master")
negative = pytest.mark.negative
positive = pytest.mark.positive

@master
@pytest.fixture
def create_delete_banner(ansible_module):
    bannertext = ("WARNING!\n"
                  "Access to this service is restricted to those individuals with\n"
                  "specific permissions. If you are not an authorized user, disconnect\n"
                  "now. Any attempts to gain unauthorized access will be prosecuted to\n"
                  "the fullest extent of the law.\n"
                  )
    ansible_module.file(path="/tmp/banner.txt", state="touch")
    ansible_module.copy(content=bannertext, dest="/tmp/banner.txt")
    ansible_module.command("cp /tmp/banner.txt /etc/pki/%s/" % constants.CA_INSTANCE_NAME)
    yield
    ansible_module.command("rm -rf /etc/pki/%s/banner.txt" % constants.CA_INSTANCE_NAME)

@master
@pytest.fixture
def import_admin_certs(ansible_module):
    ansible_module.command("mkdir /opt/tmp_nssdb")
    ansible_module.command("pki -d /opt/tmp_nssdb -c Secret123 client-init")
    ansible_module.command("pki -d /opt/tmp_nssdb -c Secret123 -h pki1.example.com -p %s client-cert-import \"RootCA\" --ca-server" % constants.CA_HTTP_PORT)
    ansible_module.command("pki -d /opt/tmp_nssdb -c Secret123 client-cert-import  --pkcs12 /opt/topology-02-CA/ca_admin_cert.p12  --pkcs12-password Secret123")
    yield
    ansible_module.command("rm -rf /opt/tmp_nssdb")

@master
@positive
@pytest.mark.parametrize("bannercmd, inputhelp, expected",
    [("banner-validate", "--help", ["Usage: pki-server banner-validate [OPTIONS]",
                                   "-i, --instance <instance ID>    Instance ID (default: pki-tomcat)",
                                   "--file <path>               Validate specified banner file."]),
    ("banner-show", "--help", ["Usage: pki-server banner-show [OPTIONS]",
                               "-i, --instance <instance ID>    Instance ID (default: pki-tomcat)",
                               "-v, --verbose                   Run in verbose mode.",
                               "--help                      Show help message."])])
def test_banner_help(ansible_module, bannercmd, inputhelp, expected):
    """
    :id: 3fb4074f-5870-4703-9b95-41c6964ff4d6
    :Title: Test banner-validate and banner-show --help command
    :Description: Command should show help result for banner show and banner validate
    :Requirement: Common Criteria - Banner configurable advisory warning banner before establishing a privileged user session
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. run command pki-server banner-show --help
        2. run command pki-server banner-validate --help
    :ExpectedEesults:
        1. Help values should be returned for banner-show.
        2. Help values should be returned for banner-validate.
    :CaseComponent: \-
    """
    help_output = ansible_module.command("pki-server %s %s" % (bannercmd, inputhelp))
    for help_result in help_output.values():
        assert help_result['rc'] == 0
        for items in expected:
            assert items in help_result['stdout']

@master
@negative
def test_banner_not_installed_banner_validate(ansible_module):
    """
    :id: 2aee7415-353f-4d1a-b566-b608306e4d2e
    :Title: Test banner validate command when banner is not installed
    :Description: Command should show if banner is valid
    :Requirement: Common Criteria - Banner configurable advisory warning banner before establishing a privileged user session
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. run command pki-server banner-validate -i <instance name> without installing banner
    :ExpectedResults:
        1. message should appear stating Banner is not installed
    :CaseComponent: \-
    """
    output = ansible_module.command("pki-server banner-validate -i %s" % constants.CA_INSTANCE_NAME)
    for result in output.values():
        assert result['rc'] == 0
        assert "Banner is not installed" in result['stdout']

@master
@negative
def test_banner_not_installed_banner_show(ansible_module):
    """
    :id: 302de718-5cb1-4b73-af90-25417aac57f2
    :Title: Test banner show command when banner is not installed
    :Description: Command should show banner text
    :Requirement: Common Criteria - Banner configurable advisory warning banner before establishing a privileged user session
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. run pki-server banner-show -i <instance>
    :ExpectedResults:
       1.  Error message should appear with banner is not installed
    :CaseComponent: \-
    """
    output = ansible_module.command("pki-server banner-show -i %s" % constants.CA_INSTANCE_NAME)
    for result in output.values():
        assert result['rc'] != 0
        assert "ERROR: Banner is not installed" in result['stdout']

@master
@positive
def test_banner_is_installed_banner_show(create_delete_banner, ansible_module):
    """
    :id: 8b5a36ee-04e3-4273-a704-62b146809256
    :Title: Test banner show when banner is installed
    :Description: Command should show banner text
    :Requirement: Common Criteria - Banner configurable advisory warning banner before establishing a privileged user session
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. add banner.txt with banner contents to /etc/pki/<instance name>
        2. run command pki-server banner-show -i <instance name>
    :ExpectedResults:
        1. Banner text should be added
        2. Banner text should appear
    :CaseComponent: \-
    """
    output = ansible_module.command("pki-server banner-show -i %s" % constants.CA_INSTANCE_NAME)
    for result in output.values():
        assert result['rc'] == 0
        assert "WARNING!" in result['stdout']

@master
@positive
def test_banner_is_installed_banner_validate(create_delete_banner, ansible_module):
    """
    :id: 9bc11f53-d8a2-4067-b753-f835f3ca51c6
    :Title: Test banner validate when banner is installed
    :Description: Command should validate banner text
    :Requirement: Common Criteria - Banner configurable advisory warning banner before establishing a privileged user session
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. add banner.txt with banner contents to /etc/pki/<instance name>
        2. run command pki-server banner-validate -i <instance name>
    :ExpectedResults:
        1. Banner text should be added.
        2. Banner is valid message should appear.
    :CaseComponent: \-
    """
    output = ansible_module.command("pki-server banner-validate -i %s" % constants.CA_INSTANCE_NAME)
    for result in output.values():
        assert result['rc'] == 0
        assert "Banner is valid" in result['stdout']

@master
@positive
def test_banner_empty_banner_validate(ansible_module):
    """
    :id: f178f4a7-cfb0-42d3-b77b-66cbd17ae79f
    :Title: Test banner validate when banner is empty
    :Description: Command should validate banner text
    :Requirement: Common Criteria - Banner configurable advisory warning banner before establishing a privileged user session
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. add banner.txt with empty banner contents to /etc/pki/<instance name>
        2. run command pki-server banner-validate -i <instance name>
    :ExpectedResults:
        1. Banner text should be added.
        2. Error message should appear Banner is empty..
    :CaseComponent: \-
    """
    ansible_module.file(path="/etc/pki/%s/banner.txt" % constants.CA_INSTANCE_NAME, state="touch")
    output = ansible_module.command("pki-server banner-validate -i %s" % constants.CA_INSTANCE_NAME)
    for result in output.values():
        assert result['rc'] != 0
        assert "ERROR: Banner is empty" in result['stdout']

@master
@negative
def test_banner_empty_banner_show(ansible_module):
    """
    :id: ed999b2c-f1af-4e6f-864b-e88e1998985e
    :Title: Test banner show when banner is empty
    :Description: Command should show banner text
    :Requirement: Common Criteria - Banner configurable advisory warning banner before establishing a privileged user session
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. add banner.txt with empty banner contents to /etc/pki/<instance name>
        2. run command pki-server banner-show -i <instance name>
    :ExpectedResults:
        1. Banner text should be added.
        2. Empty banner text should appear.
    :CaseComponent: \-
    """
    ansible_module.file(path="/etc/pki/%s/banner.txt" % constants.CA_INSTANCE_NAME, state="touch")
    output_banner_show = ansible_module.command("pki-server banner-show -i %s" % constants.CA_INSTANCE_NAME)
    for result in output_banner_show.values():
        assert "" in result['stdout']

@master
@positive
def test_modify_banner_text_banner_show_banner_validate(create_delete_banner, ansible_module):
    """
    :id: bf16fb4f-c414-4278-accb-3b42af5a5097
    :Title: Test banner show and validate with modified banner text
    :Description: Command should validate banner text
    :Requirement: Common Criteria - Banner configurable advisory warning banner before establishing a privileged user session
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    :Steps:
        1. add banner.txt with modified banner contents to /etc/pki/<instance name>
        2. run command pki-server banner-validate -i <instance name>
        3. run command pki-server banner-show -i <instance name>
    :ExpectedResults:
        1. Banner text should be added.
        2. Banner is valid message should appear.
        3. modified should be present in banner text.
    :CaseComponent: \-
    """
    ansible_module.shell("echo modified >> /etc/pki/%s/banner.txt" % constants.CA_INSTANCE_NAME)
    output_banner_validate = ansible_module.command("pki-server banner-validate -i %s" % constants.CA_INSTANCE_NAME)
    for result in output_banner_validate.values():
        assert result['rc'] == 0
        assert "Banner is valid" in result['stdout']
    output_banner_show = ansible_module.command("pki-server banner-show -i %s" % constants.CA_INSTANCE_NAME)
    for result in output_banner_show.values():
        assert "modified" in result['stdout']

@master
@positive
def test_banner_reject_pki_command(create_delete_banner, import_admin_certs, ansible_module):
    """
    :id: bfce5150-3d3c-4261-8be6-90a1f4589b26
    :Title: Test reject banner when running pki command
    :Description: when banner appears on pki command execution, if user selects N command should exit with rc 0.
    :Requirement: Common Criteria - Banner configurable advisory warning banner before establishing a privileged user session
    :Setup: Use the subsystems setup in ansible to run subsystem commands and import admin certs to nssdb
    :Steps:
        1. run pki command to add user
        2. reject banner
    :ExpectedResults:
        1. command should run and banner should appear
        2. banner should be reject and command should exit with rc 0.
    :CaseComponent: \-
    """
    rand = random.randint(0, 100)
    output = ansible_module.expect(
        command='pki -d /opt/tmp_nssdb -c %s -h pki1.example.com -p %s -n "%s" user-add tuser-%s --fullName testuser-%s' % (
        constants.CA_PASSWORD, constants.CA_HTTP_PORT, constants.CA_ADMIN_NICK, rand, rand),
        responses={"\(y\/N\)\?":"N"})
    for result in output.values():
        assert result['rc'] == 0


@master
@positive
def test_banner_accept_pki_command(create_delete_banner, import_admin_certs, ansible_module):
    """
    :id: f220f425-560a-4f2d-b369-173881fb5bac
    :Title: Test accept banner when running pki command
    :Description: when banner appears on pki command execution, if user selects Y command should proceed.
    :Requirement: Common Criteria - Banner configurable advisory warning banner before establishing a privileged user session
    :Setup: Use the subsystems setup in ansible to run subsystem commands and import admin certs to nssdb.
    :Steps:
        1. run pki command to add user
        2. accept banner
    :ExpectedResults:
        1. command should run and banner should appear
        2. banner should be accepted and command should proceed further.
    :CaseComponent: \-
    """
    rand = random.randint(0, 100)
    output = ansible_module.expect(
        command='pki -d /opt/tmp_nssdb -c %s -h pki1.example.com -p %s -n "%s" user-add tuser-%s --fullName testuser-%s' % (
        constants.CA_PASSWORD, constants.CA_HTTP_PORT, constants.CA_ADMIN_NICK, rand, rand),
        responses={"\(y\/N\)\?": "y",
                   "Import CA certificate \(Y\/n\)\? ": "Y",
                   "CA server URI \[http:\/\/pki1.example.com\:8080\/ca\]\: ": "http:\/\/pki1.example.com\:%s\/ca" % constants.CA_HTTP_PORT})
    for result in output.values():
        assert "Added user \"tuser-%s\"" % rand in result['stdout']

@master
@positive
def test_ignore_banner_pki_command(create_delete_banner, import_admin_certs, ansible_module):
    """
    :id: 5c628594-5b47-44b2-afda-6a53c9daadaa
    :Title: Test ignore banner with pki command
    :Description: Banner should not appear when pki command is run with --ignore banner.
    :Requirement: Common Criteria - Banner configurable advisory warning banner before establishing a privileged user session
    :Setup: Use the subsystems setup in ansible to run subsystem commands and import admin certs to nssdb
    :Steps:
        1. run pki command with ignore banner option.
    :ExpectedResults:
        1. Banner should not appear.
    :CaseComponent: \-
    """
    rand = random.randint(0, 100)
    output = ansible_module.expect(
        command='pki -d /opt/tmp_nssdb -c %s -h pki1.example.com -p %s --ignore-banner -n "%s" user-add tuser-%s --fullName testuser-%s' % (
        constants.CA_PASSWORD, constants.CA_HTTP_PORT, constants.CA_ADMIN_NICK, rand, rand),
        responses={"Import CA certificate \(Y\/n\)\? ": "Y",
                   "CA server URI \[http:\/\/pki1.example.com\:8080\/ca\]\: ": "http:\/\/pki1.example.com\:%s\/ca" % constants.CA_HTTP_PORT})
    for result in output.values():
        assert "Added user \"tuser-%s\"" % rand in result['stdout']

@master
@positive
def test_ignore_banner_specified_in_userspace_pki_command(create_delete_banner, import_admin_certs, ansible_module):
    """
    :id: c834fc6e-8a4d-48d6-afaf-cbab1945ee5e
    :Title: Test ignore banner with pki command defined in user space.
    :Description: Banner should not appear when PKI_CLI_OPTIONS=--ignore banner is defined in ~/.dogtag/pki.conf.
    :Requirement: Common Criteria - Banner configurable advisory warning banner before establishing a privileged user session
    :Setup: Use the subsystems setup in ansible to run subsystem commands and import admin certs to nssdb
    :Steps:
        1. run pki command.
    :ExpectedResults:
        1. banner should not appear.
    :CaseComponent: \-
    """
    rand = random.randint(0, 100)
    clioption="PKI_CLI_OPTIONS=--ignore-banner"
    ansible_module.file(path='~/.dogtag', state="directory")
    ansible_module.file(path="~/.dogtag/pki.conf", state="touch")
    ansible_module.copy(content=clioption, dest="~/.dogtag/pki.conf")
    output = ansible_module.expect(
        command='pki -d /opt/tmp_nssdb -c %s -h pki1.example.com -p %s -n "%s" user-add tuser-%s --fullName testuser-%s' % (
            constants.CA_PASSWORD, constants.CA_HTTP_PORT, constants.CA_ADMIN_NICK, rand, rand),
        responses={"Import CA certificate \(Y\/n\)\? ": "Y",
                   "CA server URI \[http:\/\/pki1.example.com\:8080\/ca\]\: ": "http:\/\/pki1.example.com\:%s\/ca" % constants.CA_HTTP_PORT})
    for result in output.values():
        assert "Added user \"tuser-%s\"" % rand in result['stdout']
    ansible_module.command("rm -rf ~/.dogtag")
