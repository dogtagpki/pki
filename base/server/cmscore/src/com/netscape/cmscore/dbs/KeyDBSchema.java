// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cmscore.dbs;

/**
 * A class represents a collection of key record
 * specific schema information.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class KeyDBSchema {

    public static final String LDAP_OC_TOP = "top";
    public static final String LDAP_ATTR_SERIALNO = "serialno";
    public static final String LDAP_ATTR_CREATE_TIME = "dateOfCreate";
    public static final String LDAP_ATTR_MODIFY_TIME = "dateOfModify";
    public static final String LDAP_ATTR_META_INFO = "metaInfo";
    public static final String LDAP_OC_KEYRECORD = "keyRecord";
    public static final String LDAP_ATTR_OWNER_NAME = "ownerName";
    public static final String LDAP_ATTR_PRIVATE_KEY_DATA = "privateKeyData";
    public static final String LDAP_ATTR_KEY_RECORD_ID = "keyRecordId";
    public static final String LDAP_ATTR_PUBLIC_KEY_DATA = "publicKeyData";
    public static final String LDAP_ATTR_KEY_SIZE = "keySize";
    public static final String LDAP_ATTR_ALGORITHM = "algorithm";
    public static final String LDAP_ATTR_STATE = "keyState";
    public static final String LDAP_ATTR_DATE_OF_RECOVERY =
            "dateOfRecovery";
    public static final String LDAP_ATTR_PUBLIC_KEY_FORMAT =
            "publicKeyFormat";
    public static final String LDAP_ATTR_ARCHIVED_BY = "archivedBy";
    public static final String LDAP_ATTR_CLIENT_ID = "clientId";
    public static final String LDAP_ATTR_STATUS = "status";
    public static final String LDAP_ATTR_DATA_TYPE = "dataType";
}
