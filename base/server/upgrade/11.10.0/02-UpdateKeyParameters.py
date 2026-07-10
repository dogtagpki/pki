# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Migrate key constraint keyParameters to allowedKeys.* (dot-separated)
# and remove keyParameters entries from on-disk CA profiles.

import logging
import os

import pki

logger = logging.getLogger(__name__)

KEY_PARAMETERS_SUFFIX = '.constraint.params.keyParameters'
MLDSA_SIZES = frozenset({'44', '65', '87'})


def classify_key_parameter_token(token, key_type=''):
    """
    Map a single keyParameters token to (family, value) for allowedKeys,
    where family is: RSA, EC, MLDSA, or MLKEM.
    """
    t = token.strip()
    if not t:
        return None
    kt = (key_type or '').strip().upper()
    if kt == 'MLKEM' and t.isdigit():
        return 'MLKEM', t
    if t in MLDSA_SIZES:
        return 'MLDSA', t
    if t.isdigit():
        return 'RSA', t
    return 'EC', t


def _parse_property_line(line):
    """
    Return (key, value) for a single-line property, or (None, None) if not a property.
    """
    s = line.lstrip()
    if not s or s.startswith('#') or '=' not in s:
        return None, None
    key, _, rest = s.partition('=')
    key = key.rstrip()
    if not key:
        return None, None
    return key, rest.lstrip().rstrip()


def _collect_property_keys(lines):
    keys = set()
    for line in lines:
        k, _ = _parse_property_line(line)
        if k:
            keys.add(k)
    return keys


def _profile_has_key_parameters(lines):
    for line in lines:
        k, _ = _parse_property_line(line)
        if k and k.endswith(KEY_PARAMETERS_SUFFIX):
            return True
    return False


def _get_constraint_key_type(lines, base):
    """Return keyType value for the key constraint at the given policy prefix."""
    key_type_key = base + 'keyType'
    for line in lines:
        k, val = _parse_property_line(line)
        if k == key_type_key:
            return (val or '').strip()
    return ''


def _remove_constraint_key_type_at_base(pf, base, basename):
    """
    Remove constraint.params.keyType at the same policy prefix as keyParameters.

    :returns: True if a keyType line was removed, False otherwise.
    """
    key_type_key = base + 'keyType'
    i = 0
    while i < len(pf.lines):
        k, _ = _parse_property_line(pf.lines[i])
        if k == key_type_key:
            pf.remove_line(i)
            logger.info('%s: removed %s', basename, key_type_key)
            return True
        i += 1
    return False


def _migrate_profile_inplace(pf):
    """
    Replace keyParameters entries with allowedKeys.* using the lines held
    in a pki.PropertyFile (preserves order, comments, and blank lines).

    :returns: True if any change was made, False otherwise.
    """
    if not _profile_has_key_parameters(pf.lines):
        return False

    basename = os.path.basename(pf.filename)
    all_keys = _collect_property_keys(pf.lines)
    changed = False
    i = 0
    while i < len(pf.lines):
        line = pf.lines[i]
        k, val = _parse_property_line(line)
        if not k or not k.endswith(KEY_PARAMETERS_SUFFIX):
            i += 1
            continue

        lead = line[:len(line) - len(line.lstrip())]
        base = k[:-len('keyParameters')]
        value = (val or '').strip()

        pf.remove_line(i)
        changed = True

        if not value:
            logger.info('%s: removed %s', basename, k)
            _remove_constraint_key_type_at_base(pf, base, basename)
            continue

        # Insert at the former keyParameters index before removing keyType.
        # keyType usually precedes keyParameters; removing it first would
        # shift default.class_id up and insert allowedKeys after it.
        insert_pos = i
        key_type = _get_constraint_key_type(pf.lines, base)
        for part in value.split(','):
            classified = classify_key_parameter_token(part, key_type)
            if classified is None:
                continue
            family, inner = classified
            ak_key = '{}allowedKeys.{}.{}'.format(base, family, inner)
            if ak_key in all_keys:
                logger.debug(
                    '%s: skip duplicate %s (already set)',
                    basename,
                    ak_key,
                )
                continue
            new_line = '{}{}=true'.format(lead, ak_key)
            pf.insert_line(insert_pos, new_line)
            all_keys.add(ak_key)
            logger.info(
                '%s: %s -> %s=true',
                basename,
                k,
                ak_key,
            )
            insert_pos += 1
        _remove_constraint_key_type_at_base(pf, base, basename)
        logger.info('%s: removed %s', basename, k)
        i = insert_pos

    return changed


class UpdateKeyParameters(pki.server.upgrade.PKIServerUpgradeScriptlet):
    """
    For each CA profile already present under the instance, move
    constraint.params.keyParameters comma-separated values into
    constraint.params.allowedKeys.<family>.<value>=true and delete the
    keyParameters and keyType properties.

    NOTE: the update does not work with LDAP stored profiles (file-based
    instance profiles only), matching 04-UpdateMLDSAProfiles.py behavior.
    """

    def __init__(self):
        super().__init__()
        self.message = 'Migrate key constraint keyParameters to allowedKeys'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        path_instance = os.path.join(subsystem.base_dir, 'profiles', 'ca')
        if not os.path.isdir(path_instance):
            logger.debug('No instance profile directory: %s', path_instance)
            return

        for file_name in sorted(os.listdir(path_instance)):
            if not file_name.endswith('.cfg'):
                continue

            path = os.path.join(path_instance, file_name)

            pf = pki.PropertyFile(path)
            pf.read()

            if not _migrate_profile_inplace(pf):
                continue

            self.backup(path)
            pf.write()
            logger.info('Storing %s', path)

        logger.info('keyParameters -> allowedKeys profile update completed')
