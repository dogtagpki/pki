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

import java.util.Enumeration;
import java.util.Hashtable;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;

/**
 * AuthenticationManager is a class for management of authentication
 * instances
 *
 * @author cfu
 */
public class AuthenticationManager
{
    private Hashtable<String, TPSAuthenticator> authInstances;

    public AuthenticationManager() {
    }

    /*
     * initAuthInstances initializes authentication manager instances
     *
     * configuration e.g.
     *
     *   auths.instance.ldap1.ui.description.en=This authenticates user against the LDAP directory.
     *   auths.instance.ldap1.ui.title.en=LDAP Authentication
     *   auths.instance.ldap1.ui.id.PASSWORD.description.en=LDAP Password
     *   auths.instance.ldap1.ui.id.PASSWORD.name.en=LDAP Password
     *   auths.instance.ldap1.ui.id.PASSWORD.credMap.authCred=pwd
     *   auths.instance.ldap1.ui.id.PASSWORD.credMap.msgCred.extlogin=PASSWORD
     *   auths.instance.ldap1.ui.id.PASSWORD.credMap.msgCred.login=password
     *   auths.instance.ldap1.ui.id.UID.description.en=LDAP User ID
     *   auths.instance.ldap1.ui.id.UID.name.en=LDAP User ID
     *   auths.instance.ldap1.ui.id.UID.credMap.authCred=uid
     *   auths.instance.ldap1.ui.id.UID.credMap.msgCred.extlogin=UID
     *   auths.instance.ldap1.ui.id.UID.credMap.msgCred.login=screen_name
     *   auths.instance.ldap1.ui.retries=1
     *
     *   # the following are handled by the IAuthManager itself
     *   auths.instance.ldap1.dnpattern=
     *   auths.instance.ldap1.ldap.basedn=dc=idm,dc=lab,dc=bos,dc=redhat,dc=com
     *   auths.instance.ldap1.ldap.ldapauth.authtype=BasicAuth
     *   auths.instance.ldap1.ldap.ldapauth.bindDN=
     *   auths.instance.ldap1.ldap.ldapauth.bindPWPrompt=ldap1
     *   auths.instance.ldap1.ldap.ldapauth.clientCertNickname=
     *   auths.instance.ldap1.ldap.ldapconn.host=vm-060.idm.lab.bos.redhat.com
     *   auths.instance.ldap1.ldap.ldapconn.port=389
     *   auths.instance.ldap1.ldap.ldapconn.secureConn=False
     *   auths.instance.ldap1.ldap.ldapconn.version=3
     *   auths.instance.ldap1.ldap.maxConns=15
     *   auths.instance.ldap1.ldap.minConns=3
     *   auths.instance.ldap1.ldapByteAttributes=
     *   auths.instance.ldap1.ldapStringAttributes=mail,cn,uid
     *   auths.instance.ldap1.pluginName=UidPwdDirAuth
     */
    public void initAuthInstances() throws EBaseException {
        CMS.debug("AuthenticationManager: initAuthInstances(): begins.");
        IConfigStore conf = CMS.getConfigStore();
        IConfigStore authInstSubstore = conf.getSubStore("auths.instance");
        Enumeration<String> auth_enu = authInstSubstore.getSubStoreNames();
        authInstances = new Hashtable<String, TPSAuthenticator>();
        while (auth_enu.hasMoreElements()) {
            String authInstID = auth_enu.nextElement();
            CMS.debug("AuthenticationManager: initAuthInstances(): initializing authentication instance " + authInstID);
            IConfigStore authInstSub =
                    authInstSubstore.getSubStore(authInstID);
            TPSAuthenticator authInst =
                    createAuthentication(authInstSub, authInstID);
            authInstances.put(authInstID, authInst);
            CMS.debug("AuthenticationManager: initAuthInstances(): authentication instance "
                    + authInstID +
                    " initialized.");
        }
        CMS.debug("AuthenticationManager: initAuthInstances(): ends.");
    }

    /*
     * createAuthentication creates and returns an Authenticaiton
     *
     * @param conf config store of the authentication instance
     * @return Authentication the authentication instance
     */
    private TPSAuthenticator createAuthentication(IConfigStore conf, String authInstID)
            throws EBaseException {

        CMS.debug("AuthenticationManager: createAuthentication(): begins for " +
                authInstID);

        if (conf == null || conf.size() <= 0) {
            CMS.debug("AuthenticationManager: createAuthentication(): conf null or empty.");
            throw new EBaseException("called with null config store");
        }

        TPSAuthenticator auth = new TPSAuthenticator(authInstID);

        IConfigStore uiSub = conf.getSubStore("ui");
        if (uiSub == null) {
            CMS.debug("AuthenticationManager: createAuthentication(): conf "
                    + conf.getName() + ".ui" + " null or empty.");
            throw new EBaseException("config " + conf.getName() + ".ui" + " not found");
        }

        // init ui title
        IConfigStore uiTitleSub = uiSub.getSubStore("title");
        if (uiTitleSub == null) {
            CMS.debug("AuthenticationManager: createAuthentication(): conf "
                    + uiSub.getName() + ".title" + " null or empty.");
            throw new EBaseException("config " + uiSub.getName() + ".title" + " not found");
        }

        Enumeration<String> uiTitle_enu = uiTitleSub.getPropertyNames();

        while (uiTitle_enu.hasMoreElements()) {
            String locale = uiTitle_enu.nextElement();
            String title = uiTitleSub.getString(locale);
            if (title.isEmpty()) {
                CMS.debug("AuthenticationManager: createAuthentication(): title for locale "
                        + locale + " not found");
                continue;
            }
            auth.setUiTitle(locale, title);
            CMS.debug("AuthenticationManager: createAuthentication(): added title="
                    + title + ", locale= " + locale);
        }

        // init ui description
        IConfigStore uiDescSub = uiSub.getSubStore("description");
        if (uiDescSub == null) {
            CMS.debug("AuthenticationManager: createAuthentication(): conf "
                    + uiSub.getName() + ".description" + " null or empty.");
            throw new EBaseException("config " + uiSub.getName() + ".description" + " not found");
        }
        Enumeration<String> uiDesc_enu = uiDescSub.getPropertyNames();

        while (uiDesc_enu.hasMoreElements()) {
            String locale = uiDesc_enu.nextElement();
            String description = uiDescSub.getString(locale);
            if (description.isEmpty()) {
                CMS.debug("AuthenticationManager: createAuthentication(): description for locale "
                        + locale + " not found");
                continue;
            }
            auth.setUiDescription(locale, description);
            CMS.debug("AuthenticationManager: createAuthentication(): added description="
                    + description + ", locale= " + locale);
        }

        // init ui parameters
        IConfigStore uiParamSub = uiSub.getSubStore("id");
        if (uiParamSub == null) {
            CMS.debug("AuthenticationManager: createAuthentication(): conf "
                    + uiSub.getName() + ".id" + " null or empty.");
            throw new EBaseException("config " + uiSub.getName() + ".id" + " not found");
        }
        Enumeration<String> uiParam_enu = uiParamSub.getSubStoreNames();
        while (uiParam_enu.hasMoreElements()) {
            String id = uiParam_enu.nextElement();
            CMS.debug("AuthenticationManager: createAuthentication(): id param=" +
                    id);
            IConfigStore idNameSub = uiParamSub.getSubStore(id + ".name");
            if (idNameSub == null) {
                CMS.debug("AuthenticationManager: createAuthentication(): conf "
                        + uiParamSub.getName() + ".name" + " null or empty.");
                continue;
            }

            AuthUIParameter up = new AuthUIParameter(id);
            Enumeration<String> idName_enu = idNameSub.getPropertyNames();
            while (idName_enu.hasMoreElements()) {
                String locale = idName_enu.nextElement();
                String name = idNameSub.getString(locale);
                if (name.isEmpty()) {
                    CMS.debug("AuthenticationManager: createAuthentication(): name for locale "
                            + locale + " not found");
                    continue;
                }
                CMS.debug("AuthenticationManager: createAuthentication(): name =" +
                        name + " for locale " + locale);
                up.setParamName(locale, name);
            }

            IConfigStore idDescSub = uiParamSub.getSubStore(id + ".description");
            if (idDescSub == null) {
                CMS.debug("AuthenticationManager: createAuthentication(): conf "
                        + uiParamSub.getName() + ".description" + " null or empty.");
                continue;
            }
            Enumeration<String> idDesc_enu = idDescSub.getPropertyNames();
            while (idDesc_enu.hasMoreElements()) {
                String locale = idDesc_enu.nextElement();
                String desc = idDescSub.getString(locale);
                if (desc.isEmpty()) {
                    CMS.debug("AuthenticationManager: createAuthentication(): description for locale "
                            + locale + " not found");
                    continue;
                }
                CMS.debug("AuthenticationManager: createAuthentication(): desc =" +
                        desc);
                up.setParamDescription(locale, desc);
            }

            auth.setUiParam(id, up);
            CMS.debug("AuthenticationManager: createAuthentication(): added param="
                    + id);

            // map the auth mgr required cred to cred name in request message
            IConfigStore credMapSub = uiParamSub.getSubStore(id + ".credMap");
            if (credMapSub == null) {
                CMS.debug("AuthenticationManager: createAuthentication(): conf "
                        + uiParamSub.getName() + ".credMap" + " null or empty.");
                continue;
            }
            String authCred = credMapSub.getString("authCred");
            if (authCred.isEmpty()) {
                CMS.debug("AuthenticationManager: createAuthentication(): conf "
                        + credMapSub.getName() + ".authCred" + " null or empty.");
                continue;
            }

            IConfigStore msgCredSub = credMapSub.getSubStore("msgCred");
            if (msgCredSub == null) {
                CMS.debug("AuthenticationManager: createAuthentication(): conf "
                        + uiParamSub.getName() + ".msgCred" + " null or empty.");
                continue;
            }

            String msgCred_login = msgCredSub.getString("login");
            if (msgCred_login.isEmpty()) {
                CMS.debug("AuthenticationManager: createAuthentication(): conf "
                        + msgCredSub.getName() + ".login" + " null or empty.");
                continue;
            }
            auth.setCredMap(authCred, msgCred_login,
                    false /* not extendedLogin*/);
            CMS.debug("AuthenticationManager: createAuthentication(): added cred map_login="
                    + authCred + ":" + msgCred_login);

            String msgCred_extlogin = msgCredSub.getString("extlogin");
            if (msgCred_extlogin.isEmpty()) {
                CMS.debug("AuthenticationManager: createAuthentication(): conf "
                        + msgCredSub.getName() + ".extlogin" + " null or empty.");
                continue;
            }

            auth.setCredMap(authCred, msgCred_extlogin,
                    true /* extendedLogin*/);
            CMS.debug("AuthenticationManager: createAuthentication(): added cred map_extlogin="
                    + authCred + ":" + msgCred_extlogin);

        }

        Integer retries = uiSub.getInteger("retries", 1);
        auth.setNumOfRetries(retries.intValue());

        CMS.debug("AuthenticationManager: createAuthentication(): completed for " +
                authInstID);
        return auth;
    }

    /*
     * gets an established Authentication instance
     */
    public TPSAuthenticator getAuthInstance(String id) {
        return authInstances.get(id);
    }
}
