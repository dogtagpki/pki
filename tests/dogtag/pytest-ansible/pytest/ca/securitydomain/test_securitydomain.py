"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI SECURITYDOMAIN CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following pki securitydomain commands needs to be tested:
#   pki securitydomain --help
#   pki securitydomain-show
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Amol Kahat <akahat@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2016 Red Hat, Inc. All rights reserved.
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
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""

import os
import sys

import pytest

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants

cmd = 'securitydomain-show'
topology = constants.CA_INSTANCE_NAME.split("-")[-1]


def test_securitydomain_command(ansible_module):
    """
    :id: e0f327ef-5471-421f-8151-7ae7b3f7b4dd
    
    :Title: RHCS-TC Test pki securitydomain --help command
    
    :Test: Test pki securitydomain --help command
    
    :Description: This command will show securitydomain help message.
    
    :Requirement: Securitydomain
    
    :CaseComponent: \-
    
    :Setup:
    
    :Steps:
            1. Run pki securitydomain --help
            
    :Expectedresults:
                1. It will show securitydomain sub commands, like securitydomain-show.
    """
    securitydomain_out = ansible_module.pki(cli='securitydomain',
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,
                                            port=constants.CA_HTTP_PORT,
                                            extra_args='--help')
    for host, result in securitydomain_out.items():
        if result['rc'] == 0:
            assert "securitydomain-show               Show domain info" in result['stdout']
        else:
            pytest.xfail("Failed to run pki securitydomain --help command")


@pytest.mark.parametrize('args', ('', '--help'))
def test_securitydomain_show_help_command(ansible_module, args):
    """
    :id: 1ab8c27e-9eac-4d8d-a697-54752d6c75ce
    
    :Title: RHCS-TC Test pki securitydomain-show --help command
    
    :Test: Test pki securitydomain-show --help command.
    
    :Description: This test will show the help message of securitydomain-show command
    
    :Requirement: Securitydomain
    
    :CaseComponent: \-
    
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    
    :Steps:
            1. Test pki securitydomain-show --help command
            
    :Expectedresults:
                1. It will show help message for command.
    """
    securitydomain_out = ansible_module.pki(cli=cmd,
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,
                                            port=constants.CA_HTTP_PORT,
                                            extra_args=args)
    for host, result in securitydomain_out.items():
        if result['rc'] == 0:
            if args == '--help':
                assert "usage: securitydomain-show [OPTIONS...]" in result['stdout']
                assert "--help      Show help message" in result['stdout']
            else:
                assert '  Domain: {}'.format(constants.CA_SECURITY_DOMAIN_NAME) in result['stdout']

                # Check for CA subsystem
                assert "  CA Subsystem:" in result['stdout']
                assert "    Host ID: CA {} {}".format('pki1.example.com', constants.CA_HTTPS_PORT) in \
                       result['stdout']
                assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
                assert "    Port: {}".format(constants.CA_HTTP_PORT) in result['stdout']
                assert "    Secure Port: {}".format(constants.CA_HTTPS_PORT) in result['stdout']
                assert "    Domain Manager: TRUE" in result['stdout']

        else:
            pytest.xfail("Failed to run pki securitydomain-show {} command".format(args))

@pytest.mark.skipif("topology >= 3")
def test_securitydomain_show_command(ansible_module):
    """
    :id: 84cf2bc8-540b-470d-aaab-3461a4e98172

    :Title: RHCS-TC Test pki securitydomain-show command with topology-01 and topology-02.

    :Test: Test pki securitydomain-show command with topology-01 and topology-02.

    :Description: This command will show securitydomain information for topology-01 and topology-02.

    :Requirement: Securitydomain

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Run pki securitydomain-show

    :Expectedresults:
                1. It should show the securitydomain information.
    """
    securitydomain_out = ansible_module.pki(cli=cmd,
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,
                                            port=constants.CA_HTTP_PORT)
    for host, result in securitydomain_out.items():

        if result['rc'] == 0:
            assert '  Domain: {}'.format(constants.CA_SECURITY_DOMAIN_NAME) in result['stdout']

            # Check for CA subsystem
            assert "  CA Subsystem:" in result['stdout']
            assert "    Host ID: CA {} {}".format('pki1.example.com', constants.CA_HTTPS_PORT) in \
                   result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: TRUE" in result['stdout']

            # Check for KRA subsystem
            assert " KRA Subsystem:" in result['stdout']
            assert "    Host ID: KRA {} {}".format('pki1.example.com', constants.KRA_HTTPS_PORT) \
                   in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.KRA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for OCSP subsystem
            assert " OCSP Subsystem:" in result['stdout']
            assert "    Host ID: OCSP {} {}".format('pki1.example.com',
                                                    constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.OCSP_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for TKS subsystem
            assert " TKS Subsystem:" in result['stdout']
            assert "    Host ID: TKS {} {}".format('pki1.example.com', constants.TKS_HTTPS_PORT) \
                   in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.TKS_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.TKS_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for TPS subsystem

            assert " TPS Subsystem:" in result['stdout']
            assert "    Host ID: TPS {} {}".format('pki1.example.com', constants.TPS_HTTPS_PORT) \
                   in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.TPS_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.TPS_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']
        else:
            pytest.xfail("Failed to run pki securitydomain-show command")


@pytest.mark.skipif("topology >= 3")
@pytest.mark.parametrize('certs', (['CA_AgentV', 'CA_AdminV', 'CA_AuditV']))
def test_securitydomain_show_command_with_valid_certs(ansible_module, certs):
    """
    :id: 5536e72f-032a-4c18-ba48-432417ea972b

    :Title: RHCS-TC Test pki securitydomain-show command with valid admin certificate for 
            topology-02 and topology-01

    :Test: Test pki securitydomain-show command with valid admin certificate for topology-02
            and topology-01

    :Description: pki securitydomain-show with different valid certificate should show the
                  securitydomain information.

    :Requirement: Securitydomain

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Run pki -n 'CA_AdminV' securitydomain-show
            2. Run pki -n 'CA_AgentV' securitydomain-show
            3. Run pki -n 'CA_AuditV' securitydomain-show

    :Expectedresults:
                1. It should show securitydomain information for topology-02 and topology-01.
                2. It should show securitydomain information for topology-02 and topology-01.
                3. It should show securitydomain information for topology-02 and topology-01.
    """
    securitydomain_out = ansible_module.pki(cli=cmd,
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,
                                            port=constants.CA_HTTP_PORT,
                                            certnick='"{}"'.format(certs))
    for host, result in securitydomain_out.items():

        if result['rc'] == 0:
            assert '  Domain: {}'.format(constants.CA_SECURITY_DOMAIN_NAME) in result['stdout']

            # Check for CA subsystem
            assert "  CA Subsystem:" in result['stdout']
            assert "    Host ID: CA {} {}".format('pki1.example.com', constants.CA_HTTPS_PORT) in \
                   result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: TRUE" in result['stdout']

            # Check for KRA subsystem
            assert " KRA Subsystem:" in result['stdout']
            assert "    Host ID: KRA {} {}".format('pki1.example.com', constants.KRA_HTTPS_PORT) \
                   in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.KRA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for OCSP subsystem
            assert " OCSP Subsystem:" in result['stdout']
            assert "    Host ID: OCSP {} {}".format('pki1.example.com',
                                                    constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.OCSP_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for TKS subsystem
            assert " TKS Subsystem:" in result['stdout']
            assert "    Host ID: TKS {} {}".format('pki1.example.com', constants.TKS_HTTPS_PORT) \
                   in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.TKS_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.TKS_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for TPS subsystem

            assert " TPS Subsystem:" in result['stdout']
            assert "    Host ID: TPS {} {}".format('pki1.example.com', constants.TPS_HTTPS_PORT) \
                   in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.TPS_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.TPS_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']
        else:
            pytest.xfail("Failed to run pki securitydomain-show command")


@pytest.mark.skipif("topology != 3")
def test_securitydomain_show_for_topology_03(ansible_module):
    """
    :id: 381eee0d-1105-414a-aeb2-9526677151d9

    :Title: RHCS-TC Test pki securitydomain-show command with topology-03.

    :Test: Test pki securitydomain-show command with topology-03.

    :Description: This command will show securitydomain information for topology-03.

    :Requirement: Securitydomain

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Run pki securitydomain-show

    :Expectedresults:
                1. It should show the securitydomain information.
    """
    securitydomain_out = ansible_module.pki(cli=cmd,
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,
                                            port=constants.CA_HTTP_PORT)
    for host, result in securitydomain_out.items():

        if result['rc'] == 0:
            assert '  Domain: {}'.format(constants.CA_SECURITY_DOMAIN_NAME) in result['stdout']

            # Check for CA subsystem
            assert "  CA Subsystem:" in result['stdout']
            assert "    Host ID: CA {} {}".format('pki1.example.com',constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: TRUE" in result['stdout']

            # Check for KRA subsystem
            assert " KRA Subsystem:" in result['stdout']
            assert"    Host ID: KRA {} {}".format('pki1.example.com', constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.KRA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for OCSP subsystem
            assert " OCSP Subsystem:" in result['stdout']
            assert "    Host ID: OCSP {} {}".format('pki1.example.com', constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.OCSP_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

        else:
            pytest.xfail("Failed to run pki securitydomain-show command for topology 03.")

@pytest.mark.skipif("topology != 3")
@pytest.mark.parametrize('certs', (['CA_AgentV', 'CA_AdminV', 'CA_AuditV']))
def test_securitydomain_show_with_valid_admin_cert_for_topology_03(ansible_module, certs):
    """
    :id: 7eb499ea-55ff-404d-a07d-3f9a2667f12c

    :Title: RHCS-TC Test pki securitydomain-show command with valid admin certificate for 
            topology-03

    :Test: Test pki securitydomain-show command with valid admin certificate for topology-03

    :Description: pki securitydomain-show with different valid certificate should show the
                  securitydomain information.

    :Requirement: Securitydomain

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Run pki -n 'CA_AdminV' securitydomain-show
            2. Run pki -n 'CA_AgentV' securitydomain-show
            3. Run pki -n 'CA_AuditV' securitydomain-show

    :Expectedresults:
                1. It should show securitydomain information for topology-03.
                2. It should show securitydomain information for topology-03.
                3. It should show securitydomain information for topology-03.
    """
    securitydomain_out = ansible_module.pki(cli=cmd,
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,
                                            port=constants.CA_HTTP_PORT,
                                            certnick='"{}"'.format(certs))
    for host, result in securitydomain_out.items():

        if result['rc'] == 0:
            assert '  Domain: {}'.format(constants.CA_SECURITY_DOMAIN_NAME) in result['stdout']

            # Check for CA subsystem
            assert "  CA Subsystem:" in result['stdout']
            assert "    Host ID: CA {} {}".format('pki1.example.com',
                                                  constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: TRUE" in result['stdout']

            # Check for KRA subsystem
            assert " KRA Subsystem:" in result['stdout']
            assert "    Host ID: KRA {} {}".format('pki1.example.com',
                                                   constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.KRA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for OCSP subsystem
            assert " OCSP Subsystem:" in result['stdout']
            assert "    Host ID: OCSP {} {}".format('pki1.example.com',
                                                    constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.OCSP_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

        else:
            pytest.xfail("Failed to run pki securitydomain-show command for topology 03.")

@pytest.mark.skipif("topology != 4")
def test_securitydomain_show_for_topology_04(ansible_module):
    """
    :id: 3fc84722-fa57-42aa-a1cc-b134cefc20c6

    :Title: RHCS-TC Test pki securitydomain-show command with topology-04.

    :Test: Test pki securitydomain-show command with topology-04.

    :Description: This command will show securitydomain information for topology-04.

    :Requirement: Securitydomain

    :CaseComponent: \-

    :Setup: Use the subsystems setup in ansible to run subsystem commands

    :Steps:
            1. Run pki securitydomain-show

    :Expectedresults:
                1. It should show the securitydomain information.
    """

    securitydomain_out = ansible_module.pki(cli=cmd,
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,
                                            port=constants.CA_HTTP_PORT)
    for host, result in securitydomain_out.items():

        if result['rc'] == 0:
            assert '  Domain: {}'.format(constants.CA_SECURITY_DOMAIN_NAME) in result['stdout']

            # Check for CA subsystem
            assert "  CA Subsystem:" in result['stdout']
            assert "    Host ID: CA {} {}".format('pki1.example.com',
                                                  constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: TRUE" in result['stdout']

            # Check for KRA subsystem
            assert " KRA Subsystem:" in result['stdout']
            assert "    Host ID: KRA {} {}".format('pki1.example.com',
                                                   constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.KRA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for OCSP subsystem
            assert " OCSP Subsystem:" in result['stdout']
            assert "    Host ID: OCSP {} {}".format('pki1.example.com',
                                                    constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.OCSP_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']
        else:
            pytest.xfail("Failed to run pki securitydomain-show command")
        ##


@pytest.mark.skipif("topology != 4")
@pytest.mark.parametrize('certs', (['CA_AgentV', 'CA_AdminV', 'CA_AuditV']))
def test_securitydomain_show_with_valid_certs_for_topology_04(ansible_module, certs):
    """
    :id: 46bab5c8-d375-4396-b7dd-1acd1f31e859
    
    :Title: RHCS-TC Test pki securitydomain-show command with valid admin certificate for topology-04
    
    :Test: Test pki securitydomain-show command with valid admin certificate for topology-04
    
    :Description: pki securitydomain-show with different valid certificate should show the
                  securitydomain information.
    
    :Requirement: Securitydomain
    
    :CaseComponent: \-
    
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    
    :Steps:
            1. Run pki -n 'CA_AdminV' securitydomain-show
            2. Run pki -n 'CA_AgentV' securitydomain-show
            3. Run pki -n 'CA_AuditV' securitydomain-show

    :Expectedresults:
                1. It should show securitydomain information for topology-04.
                2. It should show securitydomain information for topology-04.
                3. It should show securitydomain information for topology-04.
    """
    securitydomain_out = ansible_module.pki(cli=cmd,
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,                                            port=constants.CA_HTTP_PORT,
                                            certnick='"{}"'.format(certs))
    for host, result in securitydomain_out.items():

        if result['rc'] == 0:
            assert '  Domain: {}'.format(constants.CA_SECURITY_DOMAIN_NAME) in result['stdout']

            # Check for CA subsystem
            assert "  CA Subsystem:" in result['stdout']
            assert "    Host ID: CA {} {}".format('pki1.example.com',
                                                  constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: TRUE" in result['stdout']

            # Check for KRA subsystem
            assert " KRA Subsystem:" in result['stdout']
            assert "    Host ID: KRA {} {}".format('pki1.example.com',
                                                   constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.KRA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for OCSP subsystem
            assert " OCSP Subsystem:" in result['stdout']
            assert "    Host ID: OCSP {} {}".format('pki1.example.com',
                                                    constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.OCSP_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']
        else:
            pytest.xfail("Failed to run pki -n CA_AdminV securitydomain-show command") \



@pytest.mark.skipif("topology != 5")
def test_securitydomain_show_for_topology_05(ansible_module):
    """
    :id: 656efa86-9c80-42af-becd-c3ae57377737
    
    :Title: RHCS-TC Test pki securitydomain-show command with topology-05.
    
    :Test: Test pki securitydomain-show command with topology-05.
    
    :Description: This command will show securitydomain information for topology-05.
    
    :Requirement: Securitydomain
    
    :CaseComponent: \-
    
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    
    :Steps:
            1. Run pki securitydomain-show
            
    :Expectedresults:
                1. It should show the securitydomain information.
    """
    securitydomain_out = ansible_module.pki(cli=cmd,
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,
                                            port=constants.CA_HTTP_PORT)
    for host, result in securitydomain_out.items():

        if result['rc'] == 0:
            assert '  Domain: {}'.format(constants.CA_SECURITY_DOMAIN_NAME) in result['stdout']

            # Check for CA subsystem
            assert "  CA Subsystem:" in result['stdout']
            assert "    Host ID: CA {} {}".format('pki1.example.com',
                                                  constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: TRUE" in result['stdout']

            # Check for clone CA
            assert "    Host ID: CA {} {}".format('pki1.example.com',
                                             constants.CLONECA1_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CLONECA1_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CLONECA1_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: TRUE" in result['stdout']

            # Check for KRA subsystem
            assert " KRA Subsystem:" in result['stdout']
            assert "    Host ID: KRA {} {}".format('pki1.example.com',
                                                  constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.KRA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for KRA clone subsystem
            assert "    Host ID: KRA {} {}".format('pki1.example.com',
                                       constants.CLONEKRA1_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CLONEKRA1_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CLONEKRA1_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for OCSP subsystem
            assert " OCSP Subsystem:" in result['stdout']
            assert "    Host ID: OCSP {} {}".format("pki1.example.com",constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.OCSP_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for OCSP clone subsystem
            assert "    Host ID: OCSP {}".format(constants.CLONEOCSP1_HTTPS_PORT) in \
                   result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CLONEOCSP1_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CLONEOCSP1_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for TKS subsystem
            assert " TKS Subsystem:" in result['stdout']
            assert "    Host ID: TKS {} {}".format('pki1.example.com', constants.TKS_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.TKS_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.TKS_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for TKS clone subsystem
            assert "    Host ID: TKS {} {}".format('pki1.example.com',
                                                   constants.CLONETKS1_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CLONETKS1_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CLONETKS1_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for TPS subsystem

            assert " TPS Subsystem:" in result['stdout']
            assert "    Host ID: TPS {} {}".format("pki1.example.com",
                                                   constants.TPS_HTTPS_PORT)in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.TPS_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.TPS_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

        else:
            pytest.xfail("Failed to run pki securitydomain-show command for topology-05.")

@pytest.mark.skipif("topology != 5")
@pytest.mark.parametrize('certs', (['CA_AgentV', 'CA_AdminV', 'CA_AuditV']))
def test_securitydomain_show_with_valid_certs_for_topology_05(ansible_module, certs):
    """
    :id: 50932718-32e7-4d85-81e4-b5546ead633b
    
    :Title: RHCS-TC Test pki securitydomain-show with valid certificates.
    
    :Test: Test pki securitydomain-show with valid certificates.
    
    :Description: pki securitydomain-show with different valid certificate should show the
                  securitydomain information.
    
    :Requirement: Securitydomain
    
    :CaseComponent: \-
    
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    
    :Steps:
            1. Run pki -n 'CA_AdminV' securitydomain-show
            2. Run pki -n 'CA_AgentV' securitydomain-show
            3. Run pki -n 'CA_AuditV' securitydomain-show

    :Expectedresults:
                1. It should show securitydomain information for topology-05.
                2. It should show securitydomain information for topology-05.
                3. It should show securitydomain information for topology-05.
    """
    securitydomain_out = ansible_module.pki(cli=cmd,
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,
                                            port=constants.CA_HTTP_PORT,
                                            certnick='"{}"'.format(certs))
    for host, result in securitydomain_out.items():

        if result['rc'] == 0:
            assert '  Domain: {}'.format(constants.CA_SECURITY_DOMAIN_NAME) in result['stdout']

            # Check for CA subsystem
            assert "  CA Subsystem:" in result['stdout']
            assert "    Host ID: CA {} {}".format('pki1.example.com',
                                                  constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: TRUE" in result['stdout']

            # Check for clone CA
            assert "    Host ID: CA {} {}".format('pki1.example.com',
                                             constants.CLONECA1_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CLONECA1_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CLONECA1_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: TRUE" in result['stdout']

            # Check for KRA subsystem
            assert " KRA Subsystem:" in result['stdout']
            assert "    Host ID: KRA {} {}".format('pki1.example.com',
                                                  constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.KRA_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.KRA_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for KRA clone subsystem
            assert "    Host ID: KRA {} {}".format('pki1.example.com',
                                       constants.CLONEKRA1_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CLONEKRA1_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CLONEKRA1_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for OCSP subsystem
            assert " OCSP Subsystem:" in result['stdout']
            assert "    Host ID: OCSP {} {}".format("pki1.example.com",constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.OCSP_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.OCSP_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for OCSP clone subsystem
            assert "    Host ID: OCSP {}".format(constants.CLONEOCSP1_HTTPS_PORT) in \
                   result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CLONEOCSP1_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CLONEOCSP1_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for TKS subsystem
            assert " TKS Subsystem:" in result['stdout']
            assert "    Host ID: TKS {} {}".format('pki1.example.com', constants.TKS_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.TKS_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.TKS_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for TKS clone subsystem
            assert "    Host ID: TKS {} {}".format('pki1.example.com',
                                                   constants.CLONETKS1_HTTPS_PORT) in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.CLONETKS1_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.CLONETKS1_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

            # Check for TPS subsystem

            assert " TPS Subsystem:" in result['stdout']
            assert "    Host ID: TPS {} {}".format("pki1.example.com",
                                                   constants.TPS_HTTPS_PORT)in result['stdout']
            assert "    Hostname: {}".format('pki1.example.com') in result['stdout']
            assert "    Port: {}".format(constants.TPS_HTTP_PORT) in result['stdout']
            assert "    Secure Port: {}".format(constants.TPS_HTTPS_PORT) in result['stdout']
            assert "    Domain Manager: False" in result['stdout']

        else:
            pytest.xfail("Failed to run pki securitydomain-show command for topology-05.")


def test_securitydomain_show_with_expired_admin_cert(ansible_module):
    """
    :id: bd77fd7b-de29-4f50-9e8a-f3d4a7c4f57f
    
    :Title: RHCS-TC Test pki securitydomain-show with expired admin certificate.
    
    :Test: Test pki securitydomain-show with expired admin certificate.
    
    :Description: pki securitydomain-show with expired admin certificate will throw an error.
    
    :Requirement: Securitydomain
    
    :CaseComponent: \-
    
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    
    :Steps:
            1. Run pki -n 'CA_AdminE' securitydomain-show
            
    :Expectedresults:
                1. It will throw an error: IOException: SocketException cannot write on socket
    """
    securitydomain_out = ansible_module.pki(cli=cmd,
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,
                                            port=constants.CA_HTTP_PORT,
                                            certnick='"{}"'.format('CA_AdminE'))
    for host, result in securitydomain_out.items():

        if result['rc'] >= 1:
            assert "CERTIFICATE_EXPIRED" in result['stderr']

        if result['rc'] == 0:
            pytest.xfail("Failed to run pki -n CA_AdminE securitydomain-show command")


def test_securitydomain_show_with_revoked_admin_cert(ansible_module):
    """
    :id: 33cd7818-6450-4ba4-bbbc-cdc8c4ce5760
    
    :Title: RHCS-TC Test pki securitydomain-show with revoked admin certificate.
    
    :Test: Test pki securitydomain-show with revoked admin certificate.
    
    :Description: Test pki securitydomain-show with revoked admin certificate.
                  It should throw an error
    
    :Requirement: Securitydomain
    
    :CaseComponent: \-
    
    :Setup: Use the subsystems setup in ansible to run subsystem commands
    
    :Steps:
            1. Run pki -n 'CA_AdminR' securitydomain-show
            
    :Expectedresults:
                1. It should throw an error: "PKIException: Unauthorized"
    """
    securitydomain_out = ansible_module.pki(cli=cmd,
                                            nssdb=constants.NSSDB,
                                            dbpassword=constants.CLIENT_DIR_PASSWORD,
                                            port=constants.CA_HTTP_PORT,
                                            certnick='"{}"'.format('CA_AdminR'))
    for host, result in securitydomain_out.items():

        if result['rc'] >= 1:
            assert "PKIException: Unauthorized" in result['stderr']

        if result['rc'] == 0:
            pytest.xfail("Failed to run pki -n CA_AdminR securitydomain-show command")
