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
package com.netscape.certsrv.authentication;

/**
 * AuthToken interface.
 */
public interface IAuthToken {

    /**
     * Constant for userid.
     */
    public static final String USER = "user";
    public static final String USER_DN = "userdn";
    public static final String USER_ID = "userid";
    public static final String UID = "uid";
    public static final String GROUP = "group";
    public static final String GROUPS = "groups";

    /* Subject name of the certificate request in the authenticating entry */
    public static final String TOKEN_CERT_SUBJECT = "tokenCertSubject";

    /* Subject name of the authenticated cert */
    public static final String TOKEN_AUTHENTICATED_CERT_SUBJECT = "tokenAuthenticatedCertSubject";
    /* Subject DN of the Shared Token authenticated entry */
    public static final String TOKEN_SHARED_TOKEN_AUTHENTICATED_CERT_SUBJECT = "tokenSharedTokenAuthenticatedCertSubject";

    /* NotBefore value of the certificate in the authenticating entry */
    public static final String TOKEN_CERT_NOTBEFORE = "tokenCertNotBefore";

    /* NotAfter value of the certificate in the authenticating entry */
    public static final String TOKEN_CERT_NOTAFTER = "tokenCertNotAfter";

    /* Cert Extentions value of the certificate in the authenticating entry */
    public static final String TOKEN_CERT_EXTENSIONS = "tokenCertExts";

    /* Serial number of the certificate in the authenticating entry */
    public static final String TOKEN_CERT_SERIALNUM = "certSerial";

    /**
     * Certificate to be renewed
     */
    public static final String TOKEN_CERT = "tokenCert";

    /* Certificate to be revoked */
    public static final String TOKEN_CERT_TO_REVOKE = "tokenCertToRevoke";

    /**
     * Name of the authentication manager that created the AuthToken
     * as a string.
     */
    public static final String TOKEN_AUTHMGR_INST_NAME = "authMgrInstName";

    /**
     * Time of authentication as a java.util.Date
     */
    public static final String TOKEN_AUTHTIME = "authTime";
}
