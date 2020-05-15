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
package com.netscape.cmscore.apps;

import java.io.File;
import java.nio.file.Files;
import java.text.MessageFormat;
import java.util.Locale;
import java.util.ResourceBundle;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.SessionContext;

/**
 * This represents the CMS server. Plugins can access other
 * public objects such as subsystems via this inteface.
 * This object also include a set of utility functions.
 *
 * @version $Revision$, $Date$
 */
public final class CMS {

    public static Logger logger = LoggerFactory.getLogger(CMS.class);

    // product name is provided by the server theme package
    private static final String PRODUCT_NAME_FILE = "/usr/share/pki/CS_SERVER_VERSION";

    public static final int DEBUG_OBNOXIOUS = 1;
    public static final int DEBUG_VERBOSE = 5;
    public static final int DEBUG_INFORM = 10;

    public static final String CONFIG_FILE = "CS.cfg";

    public static final int PRE_OP_MODE = 0;
    public static final int RUNNING_MODE = 1;

    private static CMSEngine engine;

    public static CMSEngine getCMSEngine() {
        return engine;
    }

    public static void setCMSEngine(CMSEngine engine) {
        CMS.engine = engine;
    }

    /**
     * Return the product name from /usr/share/pki/CS_SERVER_VERSION
     * which is provided by the server theme package.
     */
    public static String getProductName() throws Exception {

        File file = new File(PRODUCT_NAME_FILE);

        if (!file.exists()) {
            return null;
        }

        return new String(Files.readAllBytes(file.toPath())).trim();
    }

    public static String getProductVersion() {
        return System.getenv("PKI_VERSION");  // defined in tomcat.conf
    }

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param msgID message id defined in UserMessages.properties
     * @param params an array of parameters
     * @return localized user message
     */
    public static String getUserMessage(String msgID, String... params) {
        return getUserMessage(null, msgID, params);
    }

    /**
     * Retrieves the localized user message from UserMessages.properties.
     *
     * @param locale end-user locale
     * @param msgID message id defined in UserMessages.properties
     * @param params an array of parameters
     * @return localized user message
     */
    public static String getUserMessage(Locale locale, String msgID, String... params) {
        // if locale is null, try to get it out from session context
        if (locale == null) {
            SessionContext sc = SessionContext.getExistingContext();

            if (sc != null)
                locale = (Locale) sc.get(SessionContext.LOCALE);
        }
        ResourceBundle rb = null;

        if (locale == null) {
            rb = ResourceBundle.getBundle(
                        "UserMessages", Locale.ENGLISH);
        } else {
            rb = ResourceBundle.getBundle(
                        "UserMessages", locale);
        }
        String msg = rb.getString(msgID);

        if (params == null)
            return msg;
        MessageFormat mf = new MessageFormat(msg);

        return mf.format(params);
    }

    /**
     * Retrieves log message from LogMessages.properties or audit-events.properties.
     *
     * @param msgID message ID defined in LogMessages.properties or audit-events.properties
     * @param params string parameters
     * @return localized log message
     */
    public static String getLogMessage(String msgID, Object... params) {

        String bundleName;

        // check whether requested message is an audit event
        if (msgID.startsWith("LOGGING_SIGNED_AUDIT_")) {
            // get audit event from audit-events.properties
            bundleName = "audit-events";
        } else {
            // get log message from LogMessages.properties
            bundleName = "LogMessages";
        }

        ResourceBundle rb = ResourceBundle.getBundle(bundleName);
        String msg = rb.getString(msgID);

        if (params == null) {
            return msg;
        }

        MessageFormat mf = new MessageFormat(msg);

        Object escapedParams[] = new Object[params.length];
        for (int i = 0; i < params.length; i++) {
            Object param = params[i];

            if (param instanceof String) {
                escapedParams[i] = escapeLogMessageParam((String) param);
            } else {
                escapedParams[i] = param;
            }
        }

        return mf.format(escapedParams);
    }

    /** Quote a string for inclusion in a java.text.MessageFormat
     */
    private static String escapeLogMessageParam(String s) {
        if (s == null)
            return null;
        if (s.contains("{") || s.contains("}"))
            return "'" + s.replaceAll("'", "''") + "'";
        return s;
    }

    /**
     * Check whether the string is contains password
     *
     * @param name key string
     * @return whether key is a password or not
     */
    public static boolean isSensitive(String name) {
        return (name.startsWith("__") ||
                name.endsWith("password") ||
                name.endsWith("passwd") ||
                name.endsWith("pwd") ||
                name.equalsIgnoreCase("admin_password_again") ||
                name.equalsIgnoreCase("directoryManagerPwd") ||
                name.equalsIgnoreCase("bindpassword") ||
                name.equalsIgnoreCase("bindpwd") ||
                name.equalsIgnoreCase("passwd") ||
                name.equalsIgnoreCase("password") ||
                name.equalsIgnoreCase("pin") ||
                name.equalsIgnoreCase("pwd") ||
                name.equalsIgnoreCase("pwdagain") ||
                name.equalsIgnoreCase("uPasswd") ||
                name.equalsIgnoreCase("PASSWORD_CACHE_ADD") ||
                name.startsWith("p12Password") ||
                name.startsWith("serverSideKeygenP12Passwd") ||
                name.equalsIgnoreCase("host_challenge") ||
                name.equalsIgnoreCase("card_challenge") ||
                name.equalsIgnoreCase("card_cryptogram") ||
                name.equalsIgnoreCase("drm_trans_desKey") ||
                name.equalsIgnoreCase("cert_request"));
    }
}
