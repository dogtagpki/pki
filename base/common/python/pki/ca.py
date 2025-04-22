#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import logging

import pki.subsystem

logger = logging.getLogger(__name__)


class CAClient(pki.subsystem.SubsystemClient):

    def __init__(self, parent):

        super().__init__(parent, 'ca')
