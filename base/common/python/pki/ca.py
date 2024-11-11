#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import logging

logger = logging.getLogger(__name__)


class CAClient:

    def __init__(self, parent):

        self.name = 'ca'
        self.parent = parent
