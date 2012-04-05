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
package com.netscape.admin.certsrv;

import com.netscape.management.client.util.*;
import java.io.*;
import java.util.*;
import com.netscape.certsrv.common.Constants;

/**
 * Resource Boundle for the Certificate Server Admin Console
 *
 * <pre>
 *  COMPONENT NAMING CONTEXT:
 *
 *      CONTEXT = PANELNAME + <COMPONENT> + IDENTIFIER + <SUFFIX>
 *
 *  PANELNAME = UPPERCASE STRING IDENTIFIER
 *  <COMPONENT> = {"BORDER","BUTTON","TEXT","RADIOBUTTON","CHECKBOX","LIST","COMBOBOX","LABEL"}
 *  IDENTIFIER = UPPERCASE STRING COMPONENT IDENTIFIER
 *  <SUFFIX> = {"LABEL","TTIP", <VALUE>}
 *  <VALUE> = "VALUE" + {"0","1",...}
 *  + = "_"
 * </pre>
 *
 *
 * @author Jack Pan-Chen
 * @author Thomas Kwan
 * @author Christina Fu
 * @version $Revision$, $Date$
 */

public class CMSAdminResources extends ResourceBundle {

    //directory
    static final String DEFAULT_IMAGE_DIRECTORY = "com/netscape/admin/certsrv/images";
    static final String DEFAULT_THEME_IMAGE_DIRECTORY = "com/netscape/admin/certsrv/theme";

    //image files
    public static final String IMAGE_CERTICON_LARGE = "CertificateServerL.gif";
    public static final String IMAGE_CERTICON_SMALL = "CertificateServer.gif";
    public static final String IMAGE_CERTICON_MEDIUM = "cert24.gif";
    public static final String IMAGE_LOGFOLDER = "alllogfolder16n.gif";
    public static final String IMAGE_LOGOBJ = "LOGobjs.gif";
    public static final String IMAGE_LOGOBJECT = "alllogdoc16n.gif";
    public static final String IMAGE_FOLDER = "allfolder16n.gif";
    public static final String IMAGE_USERGROUP = "allgroup16n.gif";
    public static final String IMAGE_USER = "alluser16n.gif";
    public static final String IMAGE_USER_WITH_CERT = "alluserwithcert16n.gif";
    public static final String IMAGE_UGOBJECT = "UGobjs.gif";
    public static final String IMAGE_DIRTY_TAB = "red-ball-small.gif";
    public static final String IMAGE_BRANDING = "certmgmt.gif";
    public static final String IMAGE_GENERICOBJ = "genobject.gif";
    public static final String IMAGE_PLUGIN = "plug.gif";
    public static final String IMAGE_PLUGINOBJECT = "plugin.gif";
    public static final String IMAGE_PLUGINFOLDER = "pluginfolder.gif";
    public static final String IMAGE_RULEOBJECT = "rulesobj.gif";
    public static final String IMAGE_RULE = "rule-16.gif";
    public static final String IMAGE_RULE_PLUGIN = "ruleplugin-16.gif";
    public static final String IMAGE_RULE_DISABLE = "ruleDisable-16.gif";
    public static final String IMAGE_SERVLETOBJECT = "servletobj.gif";
    public static final String IMAGE_SERVLET = "servlet-16.gif";
    public static final String IMAGE_SERVLET_PLUGIN = "servlet-plugin-16.gif";
    public static final String IMAGE_AUTH = "auth.gif";
    public static final String IMAGE_AUTH_PLUGIN = "authplugin.gif";
    public static final String IMAGE_AUTHOBJECT = "authobj.gif";
    public static final String IMAGE_JOBS = "jobs.gif";
    public static final String IMAGE_JOBS_PLUGIN = "jobplugin.gif";
    public static final String IMAGE_JOBSOBJECT = "jobobj.gif";
    public static final String IMAGE_LDAPPUB = "ldapub.gif";
    public static final String IMAGE_ACLOBJECT = "aclobj.gif";
    public static final String IMAGE_ACL = "acl.gif";
    public static final String IMAGE_ACLPLUGIN = "aclplugin.gif";

    //dialog icons
    public static final String IMAGE_INFO_ICON = "messagel.gif";
    public static final String IMAGE_ERROR_ICON = "error.gif";
    public static final String IMAGE_WARN_ICON = "alertl.gif";


    /**
     * Exception resources
     */
    public final static String IOEXCEPTION = "IOEXCEPTION";
    public final static String UNKNOWNHOST = "UNKNOWNHOST";
    public final static String UNKNOWNEXCEPTION = "UNKNOWNEXCEPTION";
    public final static String AUTHENNOTSUPPORTED = "AUTHENNOTSUPPORTED";
    public final static String AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED";
    public final static String PING_FAILED = "PING_FAILED";
    public final static String SERVER_UNREACHABLE = "SERVER_UNREACHABLE";
    public final static String SERVER_NORESPONSE ="SERVER_NORESPONSE";
    public final static String SERVERCONNECTION_SERVER_CERT_IMPORTED_FAILED="SERVERCONNECTION_SERVER_CERT_IMPORTED_FAILED";
    public final static String SERVERCONNECTION_NO_CLIENT_CERT="SERVERCONNECTION_NO_CLIENT_CERT";
    public final static String SERVERCONNECTION_SERVER_CERT_DENIED="SERVERCONNECTION_SERVER_CERT_DENIED";
    public final static String SERVERCONNECTION_DIFFERENT_PWD = "SERVERCONNECTION_DIFFERENT_PWD";
    public final static String SERVERCONNECTION_TOKEN_INIT_FAILED = "SERVERCONNECTION_TOKEN_INIT_FAILED";
    public final static String PROTOCOL_ERROR = "PROTOCOL_ERROR";

    //server info panel
    public final static String CERT_SERVER_NAME = "CMSINFOPANEL_LABEL_SERVERNAME_LABEL";
    public final static String SERVER_STATUS = "CMSINFOPANEL_LABEL_STATUS_LABEL";
    public final static String SERVER_STATUS_ON = "CMSINFOPANEL_LABEL_STATUSON_LABEL";
    public final static String SERVER_STATUS_OFF = "CMSINFOPANEL_LABEL_STATUSOFF_LABEL";
    public final static String SERVER_INFO = "CMSINFOPANEL_LABEL_SERVERINFO_LABEL";

    //general items
    public final static String GENERAL_OK = "GENERAL_OK";
    public final static String GENERAL_BACK = "GENERAL_BACK";
    public final static String GENERAL_DONE = "GENERAL_DONE";
    public final static String GENERAL_NEXT = "GENERAL_NEXT";
    public final static String GENERAL_HELP = "GENERAL_HELP";
    public final static String GENERAL_CANCEL = "GENERAL_CANCEL";
    public final static String GENERAL_ERROR = "GENERAL_ERROR";
    public final static String GENERAL_QUESTION = "GENERAL_QUESTION";

    //menu items
    public final static String MENU_KEYCERT = "KEYCERT";
    public final static String MENU_REFRESH = "REFRESH";
    public final static String MENU_KEYCERT_MANAGEMENT = "CERTMANAGEMENT";
    public final static String MENU_PKCS11 = "PKCS11MANAGEMENT";
    public final static String MENU_NEWCERT = "NEWCERT";
    public final static String MENU_NEW_EXTENSION = "NEW_EXTENSION";
    public final static String MENU_NEW_POLICY = "NEW_POLICY";
    public final static String MENU_PERMISSION = "PERMISSION";
    public final static String MENU_CONFIGURE_SERVER = "Configure Server";
    public final static String MENU_CONFIGURE_SERVER_DESC = "Configure the Server";
    public final static String MENU_START_SERVER = "Start Server";
    public final static String MENU_START_SERVER_DESC = "Start the Server";
    public final static String MENU_REMOVE_SERVER = "Remove Server";
    public final static String MENU_REMOVE_SERVER_DESC = "Remove the Server";
    public final static String MENU_STOP_SERVER = "Stop Server";
    public final static String MENU_STOP_SERVER_DESC = "Stop the Server";
    public final static String MENU_RESTART_SERVER = "Restart Server";
    public final static String MENU_RESTART_SERVER_DESC = "Restart the Server";


    public final static String PROP_FILE =
	"CMSAdminRS";

    public CMSAdminResources()
    {
	mResourceSet = new ThisResourceSet(PROP_FILE);
	mResourceBundle = mResourceSet.getThisBundle(PROP_FILE,
		Locale.getDefault());
    }

    /**
     * Override of ResourceBundle, same semantics
     */
    public Object handleGetObject(String key) {
	Object o = mResourceBundle.handleGetObject(key);
	if (o == null) {
		Debug.println("**** UNDEFINED PROPERTY=" + key);
	}
	return o;
    }

    /**
     * Implementation of ResourceBundle.getKeys.
     */
    public Enumeration getKeys() {
	return mResourceBundle.getKeys();
    }

    // ==================privates====================

    private PropertyResourceBundle mResourceBundle = null;
    private ThisResourceSet mResourceSet = null;
}

class ThisResourceSet extends ResourceSet
{
	public ThisResourceSet(String s)
	{
		super(s);
	}

	public PropertyResourceBundle getThisBundle(String n, Locale l)
	{
		return super.getBundle(n, l);
	}
}
