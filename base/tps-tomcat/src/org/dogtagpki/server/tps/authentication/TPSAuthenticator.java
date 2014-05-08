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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.tps.authentication;

import java.util.HashMap;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.base.EBaseException;

/**
 * Authentication is a class for an authentication instance
 *
 * @author cfu
 */
public class TPSAuthenticator {
    private String id;
    private IAuthManager authManager;

    /*
     *  for auths instance ui <locale, value>
     *  e.g.
     *   auths.instance.ldap1.ui.description.en=
     *       This authenticates user against the LDAP directory.
     *   auths.instance.ldap1.ui.title.en=LDAP Authentication
     */
    private HashMap<String, String> uiTitle;
    private HashMap<String, String> uiDescription;

    private HashMap<String, AuthUIParameter> uiParameters;
    /*
     * credMap is for authentication manager required
     * credential names (authCred) mapping to the
     * client message credentail names (msgCred)
     * e.g.
     *   auths.instance.ldap1.ui.id.UID.credMap.authCred=uid
     *   auths.instance.ldap1.ui.id.UID.credMap.msgCred=screen_name
     *   auths.instance.ldap1.ui.id.PASSWORD.credMap.authCred=pwd
     *   auths.instance.ldap1.ui.id.PASSWORD.credMap.msgCred=password
     */
    private HashMap<String, String> credMap;

    // retries if the user entered the wrong password/securid
    private int maxLoginRetries = 1;

    /*
     * Authentication constructor
     * @param authId authentication instance id
     */
    public TPSAuthenticator(String authId)
            throws EBaseException {
        id = authId;
        // retrieves and set authentication manager
        IAuthSubsystem authSub =
                (IAuthSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);
        authManager = authSub.getAuthManager(authId);
        uiTitle = new HashMap<String, String>();
        uiDescription = new HashMap<String, String>();
        uiParameters = new HashMap<String, AuthUIParameter>();
        credMap = new HashMap<String, String>();
    }

    public String getID() {
        return id;
    }

    public IAuthManager getAuthManager() {
        return authManager;
    }

    public void setUiTitle(String locale, String title) {
        uiTitle.put(locale, title);
    }

    public String getUiTitle(String locale) {
        return uiTitle.get(locale);
    }

    public void setUiDescription(String locale, String desc) {
        uiDescription.put(locale, desc);
    }

    public String getUiDescription(String locale) {
        return uiDescription.get(locale);
    }

    public void setUiParam(String id, AuthUIParameter up) {
        uiParameters.put(id, up);
    }

    public AuthUIParameter getUiParam(String id) {
        return uiParameters.get(id);
    }

    public HashMap<String, AuthUIParameter> getUiParamSet() {
        return uiParameters;
    }

    public void setCredMap(String authCred, String msgCred) {
        credMap.put(authCred, msgCred);
    }

    public String getCredMap(String authCred) {
        return credMap.get(authCred);
    }

    public int getNumOfRetries() {
        return maxLoginRetries;
    }

    public void setNumOfRetries(int num) {
        maxLoginRetries = num;
    }
}
