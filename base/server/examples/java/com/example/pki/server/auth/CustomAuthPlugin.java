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
// (C) 2026 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package com.example.pki.server.auth;

import java.util.Enumeration;
import java.util.Locale;
import java.util.Vector;

import org.dogtagpki.server.authentication.AuthManager;
import org.dogtagpki.server.authentication.AuthManagerConfig;
import org.dogtagpki.server.authentication.AuthToken;
import org.dogtagpki.server.authentication.AuthenticationConfig;

import com.netscape.certsrv.authentication.AuthCredentials;
import com.netscape.certsrv.authentication.EInvalidCredentials;
import com.netscape.certsrv.authentication.EMissingCredential;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.profile.EProfileException;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.request.Request;

/**
 * To compile the plugin:
 * $ javac \
 *     -cp "/usr/share/pki/server/common/lib/*:/usr/share/pki/server/webapps/pki/WEB-INF/lib/*" \
 *     -d /var/lib/pki/pki-tomcat/webapps/ca/WEB-INF/classes \
 *     com/example/pki/server/auth/CustomAuthPlugin.java
 *
 * See also https://github.com/dogtagpki/pki/wiki/Creating-Authentication-Plugin.
 */
public class CustomAuthPlugin extends AuthManager {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CustomAuthPlugin.class);

    @Override
    public void init(
            AuthenticationConfig authConfig,
            String name,
            String implName,
            AuthManagerConfig authManagerConfig)
            throws EBaseException {

        logger.info("CustomAuthPlugin: Initializing " + name);
        logger.info("CustomAuthPlugin: - plugin: " + implName);

        this.authenticationConfig = authConfig;
        this.mName = name;
        this.mImplName = implName;
        this.mConfig = authManagerConfig;

        logger.info("CustomAuthPlugin: auths.* params:");
        for (Enumeration<String> e = authConfig.getPropertyNames(); e.hasMoreElements(); ) {
            String propName = e.nextElement();
            String propValue = authConfig.get(propName);
            logger.info("CustomAuthPlugin: - " + propName + ": " + propValue);
        }

        logger.info("CustomAuthPlugin: auths.instance.<name>.* params:");
        for (Enumeration<String> e = authManagerConfig.getPropertyNames(); e.hasMoreElements(); ) {
            String propName = e.nextElement();
            String propValue = authManagerConfig.get(propName);
            logger.info("CustomAuthPlugin: - " + propName + ": " + propValue);
        }
    }

    @Override
    public void init(ConfigStore config) throws EProfileException {
        logger.info("CustomAuthPlugin: Initializing CustomAuthPlugin");
        for (Enumeration<String> e = config.getPropertyNames(); e.hasMoreElements(); ) {
            String propName = e.nextElement();
            String propValue = config.get(propName);
            logger.info("CustomAuthPlugin: - " + propName + ": " + propValue);
        }
    }

    @Override
    public String getText(Locale locale) {
        logger.info("CustomAuthPlugin: Getting text");
        return null;
    }

    @Override
    public Enumeration<String> getValueNames() {
        logger.info("CustomAuthPlugin: Getting value names");

        Vector<String> v = new Vector<>();
        v.addElement("uid");
        v.addElement("pwd");

        return v.elements();
    }

    @Override
    public IDescriptor getValueDescriptor(Locale locale, String name) {
        logger.info("CustomAuthPlugin: Getting value descriptor");
        return null;
    }

    @Override
    public boolean isValueWriteable(String name) {
        logger.info("CustomAuthPlugin: " + name + " value writable: " + false);
        return false;
    }

    @Override
    public boolean isSSLClientRequired() {
        logger.info("CustomAuthPlugin: SSL client required: " + false);
        return false;
    }

    @Override
    public String[] getRequiredCreds() {
        logger.info("CustomAuthPlugin: Getting required credentials");
        return null;
    }

    @Override
    public AuthToken authenticate(AuthCredentials authCred)
            throws EMissingCredential, EInvalidCredentials, EBaseException {

        logger.info("CustomAuthPlugin: Processing authentication");

        String uid = (String) authCred.get("uid");
        String password = (String) authCred.get("pwd");

        if (!"Secret.123".equals(password)) {
            throw new EInvalidCredentials(CMS.getUserMessage("CMS_AUTHENTICATION_INVALID_CREDENTIAL"));
        }

        AuthToken authToken = new AuthToken(this);
        authToken.set(AuthToken.UID, uid);
        authToken.set(AuthToken.USER_ID, uid);

        logger.info("CustomAuthPlugin: AuthToken:");
        for (Enumeration<String> e = authToken.getElements(); e.hasMoreElements(); ) {
            String name = e.nextElement();
            Object value = authToken.get(name);
            logger.info("CustomAuthPlugin: - " + name + ": " + value);
        }

        return authToken;
    }

    @Override
    public void populate(AuthToken token, Request request) throws EProfileException {

        logger.info("CustomAuthPlugin: Populating request");

        String uid = token.getInString(AuthToken.UID);
        logger.info("CustomAuthPlugin: - UID: " + uid);

        String dn = "UID=" + uid + ",OU=people,DC=example,DC=com";
        logger.info("CustomAuthPlugin: - DN: " + dn);

        // used by AuthTokenSubjectNameDefault to initialize cert subject name
        request.setExtData(AuthManager.AUTHENTICATED_NAME, dn);
    }

    @Override
    public void shutdown() {
        logger.info("CustomAuthPlugin: Shutting down");
    }
}
