/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.util;
import java.io.Serializable;

/**
 * SimpleReferral
 * For having an LDAPConnection follow referrals by just reusing the
 * same authentication DN and password.
 *
 * @version 1.0
 * @author rweltman
 **/
public class SimpleReferral implements netscape.ldap.LDAPRebind,
                            Serializable {
	/**
	 * Just save the credentials on construction
	 *
	 * @param dn The authentication DN to use
	 * @param password The authentication password to use
	 */
    public SimpleReferral( String dn, String password ) {
		_dn = dn;
		_password = password;
	}

	/**
	 * Always returns the same credentials for referrals
	 *
	 * @param host The referred-to host (ignored)
	 * @param port The referred-to port (ignored)
	 * @return Credentials for referral-following
	 */
    public netscape.ldap.LDAPRebindAuth getRebindAuthentication( String host,
																 int port ) {
		return new netscape.ldap.LDAPRebindAuth( _dn, _password );
	}
	private String _dn;
	private String _password;
}
