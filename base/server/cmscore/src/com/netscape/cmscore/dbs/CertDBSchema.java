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
 * A class represents a collection of certificate record
 * specific schema information.
 * <P>
 *
 * @author thomask
 * @version $Revision$, $Date$
 */
public class CertDBSchema {

    public static final String LDAP_OC_TOP = "top";
    public static final String LDAP_ATTR_META_INFO = "metaInfo";
    public static final String LDAP_ATTR_SERIALNO = "serialno";
    public static final String LDAP_ATTR_CREATE_TIME = "dateOfCreate";
    public static final String LDAP_ATTR_MODIFY_TIME = "dateOfModify";
    public static final String LDAP_ATTR_PUBLIC_KEY_DATA = "publicKeyData";

    public static final String LDAP_OC_CERT_RECORD = "certificateRecord";
    public static final String LDAP_ATTR_CERT_RECORD_ID = "certRecordId";
    public static final String LDAP_ATTR_NOT_BEFORE = "notBefore";
    public static final String LDAP_ATTR_NOT_AFTER = "notAfter";
    public static final String LDAP_ATTR_SIGNED_CERT = "userCertificate";
    public static final String LDAP_ATTR_VERSION = "version";
    public static final String LDAP_ATTR_DURATION = "duration";
    public static final String LDAP_ATTR_SUBJECT = "subjectName";
    public static final String LDAP_ATTR_ALGORITHM = "algorithmId";
    public static final String LDAP_ATTR_SIGNING_ALGORITHM = "signingAlgorithmId";
    public static final String LDAP_ATTR_REVO_INFO = "revInfo";
    public static final String LDAP_ATTR_CERT_STATUS = "certStatus";
    public static final String LDAP_ATTR_AUTO_RENEW = "autoRenew";
    public static final String LDAP_ATTR_ISSUED_BY = "issuedBy";
    public static final String LDAP_ATTR_REVOKED_BY = "revokedBy";
    public static final String LDAP_ATTR_REVOKED_ON = "revokedOn";
    public static final String LDAP_ATTR_EXTENSION = "extension";
}
