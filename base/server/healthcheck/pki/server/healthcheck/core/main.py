# Authors:
#     Rob Crittenden <rcrit@redhat.com>
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import logging
import sys

from ipahealthcheck.core.core import RunChecks
from configparser import ConfigParser, ParsingError

logging.basicConfig(format='%(message)s')
logger = logging.getLogger()

DOGTAG_CONFIG_FILE = "/etc/pki/healthcheck.conf"
DOGTAG_CONFIG_SECTION = "dogtag"
DOGTAG_DEFAULT_INSTANCE = "pki-tomcat"

dogtag_config_parsed = False


def main():
    checks = RunChecks(['pkihealthcheck.registry'],
                       DOGTAG_CONFIG_FILE)
    sys.exit(checks.run_healthcheck())


def merge_dogtag_config(config):
    # TODO: Move this method into ipa-healthcheck-core library
    """
    Merge "dogtag" specific config values into the provided `config` object.
    If "dogtag" section is missing in config, appends the default instance
    name "pki-tomcat"

    :param config: config object containing prefilled values
    :return: None
    """
    global dogtag_config_parsed

    if not dogtag_config_parsed:
        logger.info("Reading Dogtag specific config values")
        parser = ConfigParser()

        try:
            parser.read(DOGTAG_CONFIG_FILE)
        except ParsingError as e:
            logger.error("Unable to parse {}: {}".format(DOGTAG_CONFIG_FILE, e))
            return

        if not parser.has_section(DOGTAG_CONFIG_SECTION):
            # If "dogtag" section is missing, initialize with default instance name
            config['ca_instance_name'] = DOGTAG_DEFAULT_INSTANCE
            config['kra_instance_name'] = DOGTAG_DEFAULT_INSTANCE
            config['ocsp_instance_name'] = DOGTAG_DEFAULT_INSTANCE
            config['tks_instance_name'] = DOGTAG_DEFAULT_INSTANCE
            config['tps_instance_name'] = DOGTAG_DEFAULT_INSTANCE

            # There is no point in re-reading the config file.
            dogtag_config_parsed = True
            return

        items = parser.items(DOGTAG_CONFIG_SECTION)

        for (key, value) in items:
            config[key] = value

        dogtag_config_parsed = True
