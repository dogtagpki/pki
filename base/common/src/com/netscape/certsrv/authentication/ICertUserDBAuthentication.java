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
// (C) 2013 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.certsrv.authentication;


/**
 * @author lhsiao
 * @author cfu
 * @version $Revision$, $Date$
 */
public interface ICertUserDBAuthentication {

    /* result auth token attributes */
    public static final String TOKEN_USERDN = "user";
    public static final String TOKEN_USER_DN = "userdn";
    public static final String TOKEN_USERID = "userid";
    public static final String TOKEN_UID = "uid";

    /* required credentials */
    public static final String CRED_CERT = IAuthManager.CRED_SSL_CLIENT_CERT;
}