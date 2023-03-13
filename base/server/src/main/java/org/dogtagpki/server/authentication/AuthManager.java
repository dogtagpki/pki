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
package org.dogtagpki.server.authentication;

import java.util.Enumeration;
import java.util.Locale;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

/**
 * Authentication Manager interface.
 *
 * This interface can also be used for profile authentication.
 * If authentication is successful, request will be processed
 * immediately. Otherwise, the request will be deferred and
 * manual approval is then required.
 */
public abstract class AuthManager {

    public static final String AUTHENTICATED_NAME = "authenticatedName";

    /* standard credential for client cert from ssl client auth */
    public static final String CRED_SSL_CLIENT_CERT = "sslClientCert";

    /* standard credential for CMC request signing cert */
    public static final String CRED_CMC_SIGNING_CERT = "cmcSigningCert";
    public static final String CRED_CMC_SELF_SIGNED = "cmcSelfSigned";

    /**
     * Standard credential for client cert's serial number from revocation.
     */
    public static final String CRED_CERT_SERIAL_TO_REVOKE = "certSerialToRevoke";
    public static final String CRED_SESSION_ID = "sessionID";
    public static final String CRED_HOST_NAME = "hostname";

    protected CMSEngine engine;
    protected AuthenticationConfig authenticationConfig;
    protected String mName;
    protected String mImplName;
    protected AuthManagerConfig mConfig;
    protected String[] mConfigParams;

    public CMSEngine getCMSEngine() {
        return engine;
    }

    public void setCMSEngine(CMSEngine engine) {
        this.engine = engine;
    }

    public AuthenticationConfig getAuthenticationConfig() {
        return authenticationConfig;
    }

    public void setAuthenticationConfig(AuthenticationConfig authenticationConfig) {
        this.authenticationConfig = authenticationConfig;
    }

    /**
     * Get the name of this authentication manager instance.
     *
     * @return the name of this authentication manager.
     */
    public String getName() {
        return mName;
    }

    /**
     * Retrieves the localizable name of this policy.
     *
     * @param locale end user locale
     * @return localized authenticator name
     */
    public String getName(Locale locale) {
        return mName;
    }

    /**
     * Get name of authentication manager plugin.
     *
     * @return the name of the authentication manager plugin.
     */
    public String getImplName() {
        return mImplName;
    }

    /**
     * Retrieves the localizable description of this policy.
     *
     * @param locale end user locale
     * @return localized authenticator description
     */
    public abstract String getText(Locale locale);

    /**
     * Get the configuration store for this authentication manager.
     *
     * @return The configuration store of this authentication manager.
     */
    public AuthManagerConfig getConfigStore() {
        return mConfig;
    }

    /**
     * Get configuration parameters for this implementation.
     * The configuration parameters returned is passed to the
     * configuration console so configuration for instances of this
     * implementation can be made through the console.
     *
     * @return a list of configuration parameters.
     * @exception EBaseException If an internal error occurred
     */
    public String[] getConfigParams() {
        return mConfigParams;
    }

    /**
     * Retrieves a list of names of the property.
     *
     * @return a list of property names
     */
    public abstract Enumeration<String> getValueNames();

    /**
     * Retrieves the descriptor of the given value
     * property by name.
     *
     * @param locale user locale
     * @param name property name
     * @return descriptor of the requested property
     */
    public abstract IDescriptor getValueDescriptor(Locale locale, String name);

    /**
     * Checks if the value of the given property should be
     * serializable into the request. Passsword or other
     * security-related value may not be desirable for
     * storage.
     *
     * @param name property name
     * @return true if the property is not security related
     */
    public abstract boolean isValueWriteable(String name);

    /**
     * Checks if this authenticator requires SSL client authentication.
     *
     * @return client authentication required or not
     */
    public abstract boolean isSSLClientRequired();

    /**
     * Initialize this authentication manager.
     *
     * @param name The name of this authentication manager instance.
     * @param implName The name of the authentication manager plugin.
     * @param config The configuration store for this authentication manager.
     * @exception EBaseException If an initialization error occurred.
     */
    public abstract void init(
            AuthenticationConfig authenticationConfig,
            String name, String implName, AuthManagerConfig config)
            throws EBaseException;

    /**
     * Initializes this default policy.
     *
     * @param config configuration store
     * @exception EProfileException failed to initialize
     */
    public abstract void init(ConfigStore config) throws EProfileException;

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
    public abstract AuthToken authenticate(AuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException;

    /**
     * Populates authentication specific information into the
     * request for auditing purposes.
     *
     * @param token authentication token
     * @param request request
     * @exception EProfileException failed to populate
     */
    public abstract void populate(AuthToken token, Request request)
            throws EProfileException;

    /**
     * Prepare this authentication manager for a shutdown.
     * Called when the server is exiting for any cleanup needed.
     */
    public abstract void shutdown();

    /**
     * Gets a list of the required credentials for this authentication manager.
     *
     * @return The required credential attributes.
     */
    public abstract String[] getRequiredCreds();
}
