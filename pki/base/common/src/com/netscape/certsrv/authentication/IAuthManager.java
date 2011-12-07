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

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

/**
 * Authentication Manager interface.
 * <P>
 * 
 * @version $Revision$, $Date$
 */
public interface IAuthManager {

    /* standard credential for client cert from ssl client auth */
    public static final String CRED_SSL_CLIENT_CERT = "sslClientCert";

    /**
     * Standard credential for client cert's serial number from revocation.
     */
    public static final String CRED_CERT_SERIAL_TO_REVOKE = "certSerialToRevoke";
    public static final String CRED_SESSION_ID = "sessionID";
    public static final String CRED_HOST_NAME = "hostname";

    /**
     * Get the name of this authentication manager instance.
     * <p>
     * 
     * @return the name of this authentication manager.
     */
    public String getName();

    /**
     * Get name of authentication manager plugin.
     * <p>
     * 
     * @return the name of the authentication manager plugin.
     */
    public String getImplName();

    /**
     * Authenticate the given credentials.
     * 
     * @param authCred The authentication credentials
     * @return authentication token
     * @exception EMissingCredential If a required credential for this
     *                authentication manager is missing.
     * @exception EInvalidCredentials If credentials cannot be authenticated.
     * @exception EBaseException If an internal error occurred.
     */
    public IAuthToken authenticate(IAuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException;

    /**
     * Initialize this authentication manager.
     * 
     * @param name The name of this authentication manager instance.
     * @param implName The name of the authentication manager plugin.
     * @param config The configuration store for this authentication manager.
     * @exception EBaseException If an initialization error occurred.
     */
    public void init(String name, String implName, IConfigStore config)
            throws EBaseException;

    /**
     * Prepare this authentication manager for a shutdown. Called when the
     * server is exiting for any cleanup needed.
     */
    public void shutdown();

    /**
     * Gets a list of the required credentials for this authentication manager.
     * 
     * @return The required credential attributes.
     */
    public String[] getRequiredCreds();

    /**
     * Get configuration parameters for this implementation. The configuration
     * parameters returned is passed to the configuration console so
     * configuration for instances of this implementation can be made through
     * the console.
     * 
     * @return a list of configuration parameters.
     * @exception EBaseException If an internal error occurred
     */
    public String[] getConfigParams() throws EBaseException;

    /**
     * Get the configuration store for this authentication manager.
     * 
     * @return The configuration store of this authentication manager.
     */
    public IConfigStore getConfigStore();
}
