# Authors:
#     Jack Magne <jmagne@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

from ipahealthcheck.core.plugin import Plugin, Registry
from pki.server.instance import PKIInstance
from pki.client import PKIConnection
from pki.system import SecurityDomainClient

from pki.server.healthcheck.core.main import merge_dogtag_config

import logging
import subprocess

logger = logging.getLogger(__name__)

# Temporary workaround to skip VERBOSE data. Fix already pushed to upstream
# freeipa-healthcheck: https://github.com/freeipa/freeipa-healthcheck/pull/126
logging.getLogger().setLevel(logging.WARNING)


class ClonesPlugin(Plugin):
    def __init__(self, registry):
        # pylint: disable=redefined-outer-name
        super(ClonesPlugin, self).__init__(registry)

        self.security_domain = None
        self.db_dir = None
        self.subsystem_token = None
        self.passwd = None

        self.master_cas = []
        self.clone_cas = []
        self.master_kras = []
        self.clone_kras = []
        self.master_ocsps = []
        self.clone_ocsps = []
        self.master_tpss = []
        self.clone_tpss = []
        self.master_tkss = []
        self.clone_tkss = []

        self.instance = PKIInstance(self.config.instance_name)

    def contact_subsystem_using_pki(
            self, subport, subhost, subsystemnick,
            token_pwd, db_path, cmd, exts=None):
        command = ["/usr/bin/pki",
                   "-p", str(subport),
                   "-h", subhost,
                   "-n", subsystemnick,
                   "-P", "https",
                   "-d", db_path,
                   "-c", token_pwd,
                   cmd]

        if exts is not None:
            command.extend(exts)

        output = None
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            output = e.output.decode('utf-8')
            return output

        output = output.decode('utf-8')

        return output

    def contact_subsystem_using_sslget(
            self, port, host, subsystemnick,
            token_pwd, db_path, params, url):

        command = ["/usr/bin/sslget"]

        if subsystemnick is not None:
            command.extend(["-n", subsystemnick])

        command.extend(["-p", token_pwd, "-d", db_path])

        if params is not None:
            command.extend(["-e", params])

        command.extend([
            "-r", url, host + ":" + port])

        logger.info(' command : %s ', command)
        output = None
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            output = e.output.decode('utf-8')
            return output

        output = output.decode('utf-8')

        return output

    def get_security_domain_data(self, host, port):
        domain_data = None

        try:
            connection = PKIConnection(protocol='http',
                                       hostname=host,
                                       port=port,
                                       verify=False)

            securityDomainClient = SecurityDomainClient(connection)
            domain_data = securityDomainClient.get_domain_info()

        except BaseException as e:
            logger.error("Internal server error %s", e)
            return domain_data

        systems = domain_data.subsystems
        for s in systems.values():
            for h in s.hosts.values():
                if s.id == 'CA':
                    if h.Clone == 'TRUE':
                        self.clone_cas.append(h)
                    else:
                        self.master_cas.append(h)
                elif s.id == 'KRA':
                    if h.Clone == 'TRUE':
                        self.clone_kras.append(h)
                    else:
                        self.master_kras.append(h)
                elif s.id == 'OCSP':
                    if h.Clone == 'TRUE':
                        self.clone_ocsps.append(h)
                    else:
                        self.master_ocsps.append(h)
                elif s.id == 'TPS':
                    if h.Clone == 'TRUE':
                        self.clone_tpss.append(h)
                    else:
                        self.master_tpss.append(h)
                elif s.id == 'TKS':
                    if h.Clone == 'TRUE':
                        self.clone_tkss.append(h)
                    else:
                        self.master_tkss.append(h)

        return domain_data

    def get_security_domain_ca(self):
        sec_domain = None
        sechost = None
        secport = None
        ca_subsystem = self.instance.get_subsystem('ca')
        if(ca_subsystem):
            # make sure this CA is the security domain
            service_host = ca_subsystem.config.get('service.machineName')
            service_port = ca_subsystem.config.get('service.unsecurePort')
            sechost = ca_subsystem.config.get('securitydomain.host')
            secport = ca_subsystem.config.get('securitydomain.httpport')

            if sechost == service_host and secport == service_port:
                sec_domain = ca_subsystem

        if sec_domain:
            self.security_domain = sec_domain
            # Set some vars we will be using later
            self.db_dir = self.security_domain.config.get('jss.configDir')
            self.subsystem_token = self.security_domain.config.get('ca.subsystem.tokenname')
            self.passwd = self.instance.get_password(self.subsystem_token)

        return sec_domain, sechost, secport


class ClonesRegistry(Registry):
    def initialize(self, framework, config, options=None):
        # Read dogtag specific config values and merge with already existing config
        # before adding it to registry
        merge_dogtag_config(config)

        super(ClonesRegistry, self).initialize(framework, config)


registry = ClonesRegistry()
