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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.netscape.cms.authentication;

import java.util.Collections;
import java.util.Enumeration;
import java.util.Locale;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthToken;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.authentication.IAuthCredentials;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.profile.IProfile;
import com.netscape.certsrv.profile.IProfileAuthenticator;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.request.IRequest;

/**
 * Pull any existing auth token from the session context.
 *
 * Use with caution as a profile authenticator; if there is a
 * session it will unconditionally approve the request
 * (subject to constraints, etc).
 */
public class SessionAuthentication
        implements IProfileAuthenticator {

    private String instName = null;
    private String implName = null;
    private IConfigStore config = null;

    public SessionAuthentication() {
    }

    public void init(String instName, String implName, IConfigStore config)
            throws EBaseException {
        this.instName = instName;
        this.implName = implName;
        this.config = config;
    }

    /**
     * Gets the name of this authentication manager.
     */
    public String getName() {
        return instName;
    }

    /**
     * Gets the plugin name of authentication manager.
     */
    public String getImplName() {
        return implName;
    }

    public boolean isSSLClientRequired() {
        return false;
    }

    /**
     * Authenticate user.
     *
     * @return the auth token from existing session context, if any.
     * @throws EMissingCredential if no auth token or no session
     */
    public IAuthToken authenticate(IAuthCredentials authCred)
            throws EMissingCredential {
        SessionContext context = SessionContext.getExistingContext();

        if (context == null)
            throw new EMissingCredential("SessionAuthentication: no session");

        IAuthToken authToken = (IAuthToken)
            context.get(SessionContext.AUTH_TOKEN);

        if (authToken == null)
            throw new EMissingCredential("SessionAuthentication: no auth token");

        return authToken;
    }

    public String[] getRequiredCreds() {
        String[] requiredCreds = { };
        return requiredCreds;
    }

    public String[] getConfigParams() {
        return null;
    }

    /**
     * prepare this authentication manager for shutdown.
     */
    public void shutdown() {
    }

    /**
     * gets the configuretion substore used by this authentication
     * manager
     *
     * @return configuration store
     */
    public IConfigStore getConfigStore() {
        return config;
    }

    // Profile-related methods

    public void init(IProfile profile, IConfigStore config) {
    }

    /**
     * Retrieves the localizable name of this policy.
     */
    public String getName(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_AGENT_NAME");
    }

    /**
     * Retrieves the localizable description of this policy.
     */
    public String getText(Locale locale) {
        return CMS.getUserMessage(locale, "CMS_AUTHENTICATION_AGENT_TEXT");
    }

    /**
     * Retrieves a list of names of the value parameter.
     */
    public Enumeration<String> getValueNames() {
        return Collections.emptyEnumeration();
    }

    public boolean isValueWriteable(String name) {
        return false;
    }

    /**
     * Retrieves the descriptor of the given value
     * parameter by name.
     */
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        return null;
    }

    public void populate(IAuthToken token, IRequest request) {
    }
}
