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

import java.lang.reflect.Method;

import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSSLSocketFactory;
import netscape.ldap.LDAPv3;

/**
 * Utility class to prepare an LDAP connection, using a clear or an
 * SSL session (using SSLava from Phaos)
 */
public class DirUtil {

	/**
	 * Set up the LDAPConnection to automatically follow referrals,
	 * using the same credentials as for the current connection
	 *
	 * @param ldc An open connection to a Directory Server
	 */
    public static void setDefaultReferralCredentials( LDAPConnection ldc ) {
		if ( ldc != null ) {
			try {
				ldc.setOption( LDAPv3.REFERRALS, Boolean.valueOf(true) );
				ldc.setOption(
					LDAPv3.REFERRALS_REBIND_PROC,
					new SimpleReferral( ldc.getAuthenticationDN(),
										ldc.getAuthenticationPassword() ) );
			} catch ( LDAPException e ) {
				Debug.println( "DirUtil.setDefaultReferralCredentials: " +
							   e );
			}
		}
	}

	/**
	 * Create an unconnected LDAPConnection object, with or without an
	 * SSL factory
	 *
	 * @param useSSL If true, use an SSL socket factory
	 * @return An LDAPConnection
	 */
    public static LDAPConnection makeLDAPConnection( boolean useSSL ) {
		LDAPConnection ldc = null;
		if ( useSSL ) {
			Object cipherSuite = getCipherSuite();
			if ( cipherSuite == null ) {
				System.err.println( "DirUtil.makeLDAPConnection: " +
									"cannot get cipher suite to " +
									"establish secure connection" );
				return null;
			}
			LDAPSSLSocketFactory sfactory =
				new LDAPSSLSocketFactory( SSL_PACKAGE, cipherSuite );
			ldc = new LDAPConnection( sfactory );
		} else {
			ldc = new LDAPConnection();
		}
		return ldc;
	}

	/**
	 * Establish an LDAPConnection with default automatic referrals
	 *
	 * @param host Host to connect to
	 * @param port Port on host to connect to
	 * @param authDN Distinguished Name for authentication
	 * @param authPassword Password for authentication
	 * @param useSSL If true, establish an SSL connection
	 * @return An LDAPConnection
	 * @throws LDAPException on any failure
	 */
	public static LDAPConnection getLDAPConnection( String host, int port,
													String authDN,
													String authPassword,
													boolean useSSL )
		                         throws LDAPException {
		try {
			LDAPConnection ldc = makeLDAPConnection( useSSL );
			if ( ldc == null ) {
				return null;
			}
			ldc.connect(host, port);

            if (authDN != null && !authDN.equals ("")){
                ldc.authenticate (3, authDN, authPassword );
            }

			setDefaultReferralCredentials( ldc );

			Debug.println( "DirUtil.getLDAPConnection(" + host + ',' +
						   port + ',' + authDN + ',' + authPassword + ")" );
			return ldc;
		} catch ( LDAPException e ) {
			Debug.println( "DirUtil.getLDAPConnection(" + host + ',' +
						   port + ',' + authDN + ',' + authPassword + "): " +
						   e );
			throw e;
		}
	}

	/**
	 * Establish an LDAPConnection with default automatic referrals
	 *
	 * @param host Host to connect to
	 * @param port Port on host to connect to
	 * @param authDN Distinguished Name for authentication
	 * @param authPassword Password for authentication
	 * @return An LDAPConnection
	 * @throws LDAPException on any failure
	 */
	public static LDAPConnection getLDAPConnection( String host, int port,
													String authDN,
													String authPassword )
		                         throws LDAPException {
	    return getLDAPConnection( host, port, authDN, authPassword, false );
	}

	private static Object getCipherSuite() {
		if ( _cipherSuite == null ) {
			try {
				Class c = Class.forName( SSL_CIPHERS );
				Method m = c.getMethod( "getCipherSuite", new Class[0] );
				_cipherSuite = m.invoke( null, (Object[])null );
			} catch (Exception e) {
				Debug.println("DirUtil.getCipherSuite: Cannot load class, " +
					e );
			}
		}
		return _cipherSuite;
	}

	// SSLava parameters
	private static Object _cipherSuite = null;
	private static final String SSL_PACKAGE = "crysec.SSL.SSLSocket";
	private static final String SSL_CIPHERS = "crysec.SSL.SSLParams";
}
