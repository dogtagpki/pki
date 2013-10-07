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
package com.netscape.cms.servlet.cert;

import java.io.IOException;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPConnection;
import netscape.ldap.LDAPEntry;
import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSearchResults;
import netscape.ldap.LDAPv2;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.AuthMgrPlugin;
import com.netscape.certsrv.authentication.IAuthManager;
import com.netscape.certsrv.authentication.IAuthSubsystem;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;

/**
 * Allow agent to turn on/off authentication managers
 *
 * @version $Revision$, $Date$
 */
public class RemoteAuthConfig extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -5803015919915253940L;
    private final static String TPL_FILE = "remoteAuthConfig.template";
    private final static String ENABLE_REMOTE_CONFIG = "enableRemoteConfiguration";
    private final static String REMOTELY_SET_INSTANCES = "remotelySetInstances";
    private final static String MEMBER_OF = "memberOf";
    private final static String UNIQUE_MEMBER = "uniqueMember";

    private String mFormPath = null;
    private IAuthSubsystem mAuthSubsystem = null;
    private IConfigStore mAuthConfig = null;
    private IConfigStore mFileConfig = null;
    private Vector<String> mRemotelySetInstances = new Vector<String>();
    private boolean mEnableRemoteConfiguration = false;

    /**
     * Constructs RemoteAuthConfig servlet.
     */
    public RemoteAuthConfig() {
        super();
    }

    /**
     * Initializes the servlet.
     *
     * Presence of "auths.enableRemoteConfiguration=true" in CMS.cfg
     * enables remote configuration for authentication plugins.
     * List of remotely set instances can be found in CMS.cfg
     * at "auths.remotelySetInstances=<name1>,<name2>,...,<nameN>"
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);

        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
        mFileConfig = CMS.getConfigStore();
        mAuthConfig = mFileConfig.getSubStore("auths");
        try {
            mEnableRemoteConfiguration = mAuthConfig.getBoolean(ENABLE_REMOTE_CONFIG, false);
        } catch (EBaseException eb) {
            // Thanks to design of getBoolean we have to catch but we will never get anything.
        }

        String remoteList = null;

        try {
            remoteList = mAuthConfig.getString(REMOTELY_SET_INSTANCES, null);
        } catch (EBaseException eb) {
            // Thanks to design of getString we have to catch but we will never get anything.
        }
        if (remoteList != null) {
            StringTokenizer s = new StringTokenizer(remoteList, ",");

            while (s.hasMoreTokens()) {
                String token = s.nextToken();

                if (token != null && token.trim().length() > 0) {
                    mRemotelySetInstances.add(token.trim());
                }
            }
        }

        mAuthSubsystem = (IAuthSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_AUTH);

        mTemplates.remove(ICMSRequest.SUCCESS);
    }

    /**
     * Serves HTTPS request. The format of this request is as follows:
     * https://host:ee-port/remoteAuthConfig?
     * op="add"|"delete"&
     * instance=<instanceName>&
     * of=<authPluginName>&
     * host=<hostName>&
     * port=<portNumber>&
     * password=<password>&
     * [adminDN=<adminDN>]&
     * [uid=<uid>]&
     * [baseDN=<baseDN>]
     */
    public void process(CMSRequest cmsReq) throws EBaseException {
        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        authenticate(cmsReq);

        IArgBlock header = CMS.createArgBlock();
        IArgBlock ctx = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, ctx);

        String host = req.getParameter("host");
        String port = req.getParameter("port");

        String adminDN = req.getParameter("adminDN");
        String uid = req.getParameter("uid");
        String baseDN = req.getParameter("baseDN");
        String password = req.getParameter("password");

        String replyTo = req.getParameter("replyTo");

        if (replyTo != null && replyTo.length() > 0) {
            ctx.addStringValue("replyTo", replyTo);
        }

        if (mEnableRemoteConfiguration) {
            String errMsg = null;

            if (adminDN != null && adminDN.length() > 0) {
                errMsg = authenticateRemoteAdmin(host, port, adminDN, password);
            } else {
                errMsg = authenticateRemoteAdmin(host, port, uid, baseDN, password);
            }
            if (errMsg == null || errMsg.length() == 0) {
                if (mAuthSubsystem != null && mAuthConfig != null) {
                    String op = req.getParameter("op");

                    if (op == null || op.length() == 0) {
                        header.addStringValue("error", "Undefined operation");
                    } else {
                        header.addStringValue("op", op);

                        if (op.equals("delete")) {
                            String plugin = req.getParameter("of");

                            if (isPluginListed(plugin)) {
                                String instance = req.getParameter("instance");

                                if (isInstanceListed(instance)) {
                                    errMsg = deleteInstance(instance);
                                    if (errMsg != null && errMsg.length() > 0) {
                                        header.addStringValue("error", errMsg);
                                    } else {
                                        header.addStringValue("plugin", plugin);
                                        header.addStringValue("instance", instance);
                                    }
                                } else {
                                    header.addStringValue("error", "Unknown instance " +
                                            instance + ".");
                                }
                            } else {
                                header.addStringValue("error", "Unknown plugin name: " + plugin);
                            }
                        } else if (op.equals("add")) {
                            String plugin = req.getParameter("of");

                            if (isPluginListed(plugin)) {
                                String instance = req.getParameter("instance");

                                if (instance == null || instance.length() == 0) {
                                    instance = makeInstanceName();
                                }
                                if (isInstanceListed(instance)) {
                                    header.addStringValue("error", "Instance name " +
                                            instance + " is already in use.");
                                } else {
                                    errMsg = addInstance(instance, plugin,
                                                host, port, baseDN,
                                                req.getParameter("dnPattern"));
                                    if (errMsg != null && errMsg.length() > 0) {
                                        header.addStringValue("error", errMsg);
                                    } else {
                                        header.addStringValue("plugin", plugin);
                                        header.addStringValue("instance", instance);
                                    }
                                }
                            } else {
                                header.addStringValue("error", "Unknown plugin name: " + plugin);
                            }
                        } else {
                            header.addStringValue("error", "Unsupported operation: " + op);
                        }
                    }
                } else {
                    header.addStringValue("error", "Invalid configuration data.");
                }
            } else {
                header.addStringValue("error", errMsg);
            }
        } else {
            header.addStringValue("error", "Remote configuration is disabled.");
        }
        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        try {
            ServletOutputStream out = resp.getOutputStream();

            resp.setContentType("text/html");
            form.renderOutput(out, argSet);
            cmsReq.setStatus(ICMSRequest.SUCCESS);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }
    }

    private String authenticateRemoteAdmin(String host, String port,
            String adminDN, String password) {
        if (host == null || host.length() == 0) {
            return "Missing host name.";
        }
        if (port == null || port.length() == 0 || port.trim().length() == 0) {
            return "Missing port number.";
        }
        if (adminDN == null || adminDN.length() == 0) {
            return "Missing admin DN.";
        }
        if (password == null || password.length() == 0) {
            return "Missing password.";
        }
        int p = 0;

        try {
            p = Integer.parseInt(port.trim());
        } catch (NumberFormatException e) {
            return "Invalid port number: " + port + " (" + e.toString() + ")";
        }

        boolean connected = false;
        LDAPConnection c = new LDAPConnection();

        try {
            c.connect(host, p);
            connected = true;
            try {
                c.authenticate(adminDN, password);
                LDAPEntry entry = c.read(adminDN);
                LDAPAttribute attr = entry.getAttribute(MEMBER_OF);

                if (attr != null) {
                    @SuppressWarnings("unchecked")
                    Enumeration<String> eVals = attr.getStringValues();

                    while (eVals.hasMoreElements()) {
                        String nextValue = eVals.nextElement();

                        if (nextValue.indexOf("Administrator") > -1) {
                            LDAPEntry groupEntry = c.read(nextValue);

                            if (groupEntry != null) {
                                LDAPAttribute gAttr = groupEntry.getAttribute(UNIQUE_MEMBER);

                                if (gAttr != null) {
                                    @SuppressWarnings("unchecked")
                                    Enumeration<String> eValues = gAttr.getStringValues();

                                    while (eValues.hasMoreElements()) {
                                        String value = eValues.nextElement();

                                        if (value.equals(entry.getDN())) {
                                            c.disconnect();
                                            return null;
                                        }
                                    }
                                }
                            }
                            break;
                        }
                    }
                } else {
                    c.disconnect();
                    return null;
                }

            } catch (LDAPException e) {

                /*
                 switch (e.getLDAPResultCode()) {
                 case LDAPException.NO_SUCH_OBJECT:
                 case LDAPException.INVALID_CREDENTIALS:
                 case LDAPException.INSUFFICIENT_ACCESS_RIGHTS:
                 case LDAPException.LDAP_PARTIAL_RESULTS:
                 default:
                 }
                 */
                c.disconnect();
                return "LDAP error: " + e.toString();
            }

            if (connected) {
                c.disconnect();
            }
        } catch (LDAPException e) {
            return "LDAP error: " + e.toString();
        }

        return "Access unauthorized";
    }

    private String authenticateRemoteAdmin(String host, String port,
            String uid, String baseDN,
            String password) {
        if (host == null || host.length() == 0) {
            return "Missing host name.";
        }
        if (port == null || port.length() == 0 || port.trim().length() == 0) {
            return "Missing port number.";
        }
        if (uid == null || uid.length() == 0) {
            return "Missing UID.";
        }
        if (uid.indexOf('*') > -1) {
            return "Invalid UID: " + uid;
        }
        if (password == null || password.length() == 0) {
            return "Missing password.";
        }
        int p = 0;

        try {
            p = Integer.parseInt(port.trim());
        } catch (NumberFormatException e) {
            return "Invalid port number: " + port + " (" + e.toString() + ")";
        }
        if (baseDN == null || baseDN.length() == 0) {
            return "Missing base DN.";
        }

        boolean connected = false;
        LDAPConnection c = new LDAPConnection();

        try {
            c.connect(host, p);
            connected = true;
            boolean memberOf = false;
            LDAPSearchResults results = c.search(baseDN, LDAPv2.SCOPE_SUB,
                    "(uid=" + uid + ")",
                    null, false);

            while (results.hasMoreElements()) {
                LDAPEntry entry = null;

                try {
                    entry = results.next();
                    c.authenticate(entry.getDN(), password);
                    LDAPAttribute attr = entry.getAttribute(MEMBER_OF);

                    if (attr != null) {
                        memberOf = true;
                        @SuppressWarnings("unchecked")
                        Enumeration<String> eVals = attr.getStringValues();

                        while (eVals.hasMoreElements()) {
                            String nextValue = eVals.nextElement();

                            if (nextValue.indexOf("Administrator") > -1) {
                                LDAPEntry groupEntry = c.read(nextValue);

                                if (groupEntry != null) {
                                    LDAPAttribute gAttr = groupEntry.getAttribute(UNIQUE_MEMBER);

                                    if (gAttr != null) {
                                        @SuppressWarnings("unchecked")
                                        Enumeration<String> eValues = gAttr.getStringValues();

                                        while (eValues.hasMoreElements()) {
                                            String value = eValues.nextElement();

                                            if (value.equals(entry.getDN())) {
                                                c.disconnect();
                                                return null;
                                            }
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                } catch (LDAPException e) {
                    switch (e.getLDAPResultCode()) {
                    case LDAPException.NO_SUCH_OBJECT:
                        continue;

                    case LDAPException.INVALID_CREDENTIALS:
                        break;

                    case LDAPException.INSUFFICIENT_ACCESS_RIGHTS:
                        break;

                    case LDAPException.LDAP_PARTIAL_RESULTS:
                        break;

                    default:
                        continue;
                    }
                }
            }
            if (connected) {
                c.disconnect();
            }

            if (!memberOf) {
                return null;
            }
        } catch (LDAPException e) {
            return "LDAP error: " + e.toString();
        }

        return "Access unauthorized";
    }

    private String addInstance(String instance, String plugin,
            String host, String port,
            String baseDN, String dnPattern) {
        if (host == null || host.length() == 0) {
            return "Missing host name.";
        }
        if (port == null || port.length() == 0) {
            return "Missing port number.";
        }

        IConfigStore c0 = mAuthConfig.getSubStore("instance");
        IConfigStore c1 = c0.makeSubStore(instance);

        c1.putString("dnpattern", dnPattern);
        c1.putString("ldapByteAttributes", "");
        c1.putString("ldapStringAttributes", "");
        c1.putString("pluginName", plugin);
        if (baseDN != null && baseDN.length() > 0)
            c1.putString("ldap.basedn", baseDN);
        c1.putString("ldap.minConns", "");
        c1.putString("ldap.maxConns", "");
        c1.putString("ldap.ldapconn.host", host);
        c1.putString("ldap.ldapconn.port", port);
        c1.putString("ldap.ldapconn.secureConn", "false");
        c1.putString("ldap.ldapconn.version", "3");

        mRemotelySetInstances.add(instance);

        IAuthManager authMgrInst = mAuthSubsystem.getAuthManagerPlugin(plugin);

        if (authMgrInst != null) {
            try {
                authMgrInst.init(instance, plugin, c1);
            } catch (EBaseException e) {
                c0.removeSubStore(instance);
                mRemotelySetInstances.remove(instance);
                return e.toString();
            }
            mAuthSubsystem.add(instance, authMgrInst);
        }

        StringBuffer list = new StringBuffer();

        for (int i = 0; i < mRemotelySetInstances.size(); i++) {
            if (i > 0)
                list.append(",");
            list.append(mRemotelySetInstances.elementAt(i));
        }

        mAuthConfig.putString(REMOTELY_SET_INSTANCES, list.toString());

        try {
            mFileConfig.commit(false);
        } catch (EBaseException e) {
            c0.removeSubStore(instance);
            mRemotelySetInstances.remove(instance);
            return e.toString();
        }

        return null;
    }

    private String deleteInstance(String instance) {
        IConfigStore c = mAuthConfig.getSubStore("instance");

        c.removeSubStore(instance);

        if (mRemotelySetInstances.remove(instance)) {
            StringBuffer list = new StringBuffer();

            for (int i = 0; i < mRemotelySetInstances.size(); i++) {
                if (i > 0)
                    list.append(",");
                list.append(mRemotelySetInstances.elementAt(i));
            }

            mAuthConfig.putString(REMOTELY_SET_INSTANCES, list.toString());
        }

        try {
            mFileConfig.commit(false);
        } catch (EBaseException e) {
            return e.toString();
        }
        mAuthSubsystem.delete(instance);

        return null;
    }

    private boolean isPluginListed(String pluginName) {
        boolean isListed = false;

        if (pluginName != null && pluginName.length() > 0) {
            Enumeration<AuthMgrPlugin> e = mAuthSubsystem.getAuthManagerPlugins();

            while (e.hasMoreElements()) {
                AuthMgrPlugin plugin = e.nextElement();

                if (pluginName.equals(plugin.getId())) {
                    isListed = true;
                    break;
                }
            }
        }

        return isListed;
    }

    private boolean isInstanceListed(String instanceName) {
        boolean isListed = false;

        if (instanceName != null && instanceName.length() > 0) {
            Enumeration<IAuthManager> e = mAuthSubsystem.getAuthManagers();

            while (e.hasMoreElements()) {
                IAuthManager authManager = e.nextElement();

                if (instanceName.equals(authManager.getName())) {
                    isListed = true;
                    break;
                }
            }
        }

        return isListed;
    }

    private String makeInstanceName() {
        Calendar now = Calendar.getInstance();
        int y = now.get(Calendar.YEAR);
        String name = "R" + y;

        if (now.get(Calendar.MONTH) < 10)
            name += "0";
        name += now.get(Calendar.MONTH);
        if (now.get(Calendar.DAY_OF_MONTH) < 10)
            name += "0";
        name += now.get(Calendar.DAY_OF_MONTH);
        if (now.get(Calendar.HOUR_OF_DAY) < 10)
            name += "0";
        name += now.get(Calendar.HOUR_OF_DAY);
        if (now.get(Calendar.MINUTE) < 10)
            name += "0";
        name += now.get(Calendar.MINUTE);
        if (now.get(Calendar.SECOND) < 10)
            name += "0";
        name += now.get(Calendar.SECOND);
        return name;
    }
}
