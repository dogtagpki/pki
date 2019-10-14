#!/usr/bin/python
# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import

import pki


class UpdateAuditEvents(
        pki.server.upgrade.PKIServerUpgradeScriptlet):

    REPLACEMENTS = [
        ['ACCESS_SESSION_ESTABLISH_FAILURE', 'ACCESS_SESSION_ESTABLISH'],
        ['ACCESS_SESSION_ESTABLISH_SUCCESS', 'ACCESS_SESSION_ESTABLISH'],
        ['AUTH_FAIL', 'AUTH'],
        ['AUTH_SUCCESS', 'AUTH'],
        ['AUTHZ_FAIL', 'AUTHZ'],
        ['AUTHZ_SUCCESS', 'AUTHZ'],
        ['ASYMKEY_GEN_REQUEST_PROCESSED', 'ASYMKEY_GENERATION_REQUEST_PROCESSED'],
        ['CMC_USER_SIGNED_REQUEST_SIG_VERIFY_FAILURE', 'CMC_USER_SIGNED_REQUEST_SIG_VERIFY'],
        ['CMC_USER_SIGNED_REQUEST_SIG_VERIFY_SUCCESS', 'CMC_USER_SIGNED_REQUEST_SIG_VERIFY'],
        ['COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_FAILURE', 'COMPUTE_RANDOM_DATA_REQUEST_PROCESSED'],
        ['COMPUTE_RANDOM_DATA_REQUEST_PROCESSED_SUCCESS', 'COMPUTE_RANDOM_DATA_REQUEST_PROCESSED'],
        ['COMPUTE_SESSION_KEY_REQUEST_PROCESSED_FAILURE', 'COMPUTE_SESSION_KEY_REQUEST_PROCESSED'],
        ['COMPUTE_SESSION_KEY_REQUEST_PROCESSED_SUCCESS', 'COMPUTE_SESSION_KEY_REQUEST_PROCESSED'],
        ['DIVERSIFY_KEY_REQUEST_PROCESSED_FAILURE', 'DIVERSIFY_KEY_REQUEST_PROCESSED'],
        ['DIVERSIFY_KEY_REQUEST_PROCESSED_SUCCESS', 'DIVERSIFY_KEY_REQUEST_PROCESSED'],
        ['ENCRYPT_DATA_REQUEST_PROCESSED_FAILURE', 'ENCRYPT_DATA_REQUEST_PROCESSED'],
        ['ENCRYPT_DATA_REQUEST_PROCESSED_SUCCESS', 'ENCRYPT_DATA_REQUEST_PROCESSED'],
        ['LOGGING_SIGNED_AUDIT_SIGNING', 'AUDIT_LOG_SIGNING'],
        ['OCSP_REMOVE_CA_REQUEST_PROCESSED_FAILURE', 'OCSP_REMOVE_CA_REQUEST_PROCESSED'],
        ['OCSP_REMOVE_CA_REQUEST_PROCESSED_SUCCESS', 'OCSP_REMOVE_CA_REQUEST_PROCESSED'],
        ['SERVER_SIDE_KEYGEN_REQUEST_PROCESSED_FAILURE', 'SERVER_SIDE_KEYGEN_REQUEST_PROCESSED'],
        ['SERVER_SIDE_KEYGEN_REQUEST_PROCESSED_SUCCESS', 'SERVER_SIDE_KEYGEN_REQUEST_PROCESSED'],
        ['SYMKEY_GEN_REQUEST_PROCESSED', 'SYMKEY_GENERATION_REQUEST_PROCESSED'],
        ['TOKEN_APPLET_UPGRADE_FAILURE', 'TOKEN_APPLET_UPGRADE'],
        ['TOKEN_APPLET_UPGRADE_SUCCESS', 'TOKEN_APPLET_UPGRADE'],
        ['TOKEN_AUTH_FAILURE', 'TOKEN_AUTH'],
        ['TOKEN_AUTH_SUCCESS', 'TOKEN_AUTH'],
        ['TOKEN_FORMAT_FAILURE', 'TOKEN_FORMAT'],
        ['TOKEN_FORMAT_SUCCESS', 'TOKEN_FORMAT'],
        ['TOKEN_KEY_CHANGEOVER_FAILURE', 'TOKEN_KEY_CHANGEOVER'],
        ['TOKEN_KEY_CHANGEOVER_SUCCESS', 'TOKEN_KEY_CHANGEOVER'],
        ['TOKEN_PIN_RESET_FAILURE', 'TOKEN_PIN_RESET'],
        ['TOKEN_PIN_RESET_SUCCESS', 'TOKEN_PIN_RESET'],
    ]

    def __init__(self):
        super(UpdateAuditEvents, self).__init__()
        self.message = 'Update audit events'

    def upgrade_subsystem(self, instance, subsystem):

        self.backup(subsystem.cs_conf)

        # update documentation
        subsystem.config['log.instance.SignedAudit._003'] = \
            '## To list available audit events:'
        subsystem.config['log.instance.SignedAudit._004'] = \
            '## $ pki-server %s-audit-event-find' % subsystem.name
        subsystem.config['log.instance.SignedAudit._005'] = \
            '##'
        subsystem.config['log.instance.SignedAudit._006'] = \
            '## To enable/disable audit event:'
        subsystem.config['log.instance.SignedAudit._007'] = \
            '## $ pki-server %s-audit-event-enable/disable <event name>' % subsystem.name
        subsystem.config['log.instance.SignedAudit._008'] = \
            '##'

        # update selected audit events
        self.update_audit_events(subsystem, 'log.instance.SignedAudit.events')

        # update mandatory audit events
        self.update_audit_events(subsystem, 'log.instance.SignedAudit.mandatory.events')

        # remove unselected audit events
        subsystem.config.pop('log.instance.SignedAudit.unselected.events', None)

        # update audit event filters
        self.update_audit_event_filters(subsystem, 'log.instance.SignedAudit.filters.')

        subsystem.save()

    def update_audit_events(self, subsystem, prop_name):

        value = subsystem.config.get(prop_name, None)
        if not value:
            return

        events = set(value.replace(' ', '').split(','))

        for replacement in UpdateAuditEvents.REPLACEMENTS:

            old_event = replacement[0]
            new_event = replacement[1]

            if old_event in events:
                events.remove(old_event)
                events.add(new_event)

        event_list = ','.join(sorted(events))
        subsystem.config[prop_name] = event_list

    def update_audit_event_filters(self, subsystem, prefix):

        prop_names = subsystem.config.keys()
        for prop_name in prop_names:

            # not a filter, skip
            if not prop_name.startswith(prefix):
                continue

            event_name = prop_name[len(prefix):]

            for replacement in UpdateAuditEvents.REPLACEMENTS:

                old_event = replacement[0]
                new_event = replacement[1]

                if event_name != old_event:
                    continue

                # remove filter for old event
                event_filter = subsystem.config.pop(prop_name)

                # add filter for new event
                prop_name = prefix + new_event
                subsystem.config[prop_name] = event_filter
