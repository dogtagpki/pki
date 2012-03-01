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
package com.netscape.cms.servlet.csadmin;


import org.apache.velocity.Template;
import org.apache.velocity.servlet.VelocityServlet;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.context.Context;
import javax.servlet.*;
import javax.servlet.http.*;

import com.netscape.certsrv.base.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.property.*;
import java.io.*;
import java.net.URL;
import com.netscape.certsrv.base.*;
import java.util.*;
import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;

import com.netscape.cms.servlet.wizard.*;

public class AdminAuthenticatePanel extends WizardPanelBase {

    public AdminAuthenticatePanel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Admin Authentication");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
        throws ServletException {
        setPanelNo(panelno);
        setName("Admin Authentication");
        setId(id);
    }

    public boolean isSubPanel() {
        return true;
    }
                                                                                
    /**
     * Should we skip this panel for the configuration.
     */
    public boolean shouldSkip() {
        CMS.debug("AdminAuthenticatePanel: should skip");
                                                                                
        IConfigStore cs = CMS.getConfigStore();
        // if we are root, no need to get the certificate chain.
                                                                                
        try {
            String select = cs.getString("preop.subsystem.select","");
            if (select.equals("new")) {
                return true;
            }
        } catch (EBaseException e) {
        }
                                                                                
        return false;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        /* clean up if necessary */
        try {
            boolean done = cs.getBoolean("preop.AdminAuthenticate.done");
            cs.putBoolean("preop.AdminAuthenticate.done", false);
            cs.commit(false);
        } catch (Exception e) {
        }
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.AdminAuthenticate.done", "");
            if (s == null || s.equals("")) {
                return false;
            } else {
                return true;
            }
        } catch (EBaseException e) {}
        return false;
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();
                                                                                
        /* XXX */
                                                                                
        return set;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("title", "Admin Authentication");
        IConfigStore config = CMS.getConfigStore();

        if (isPanelDone()) {
            
            try {
                String s = config.getString("preop.master.admin.uid", "");
                String type = config.getString("preop.subsystem.select", "");
                if (type.equals("clone"))
                    context.put("uid", s); 
                else
                    context.put("uid", "");
            } catch (Exception e) {
                CMS.debug(e.toString());
            }
        } else {
            context.put("uid", "");
        }

        context.put("password", "");
        context.put("panel", "admin/console/config/adminauthenticatepanel.vm");
        context.put("errorString", "");
    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        IConfigStore config = CMS.getConfigStore();
        String subsystemtype = "";
        String cstype = "";
        try {
            subsystemtype = config.getString("preop.subsystem.select", "");
            cstype = config.getString("cs.type", "");
        } catch (Exception e) {
        }
        cstype = toLowerCaseSubsystemType(cstype);

        if (subsystemtype.equals("clone")) {
            CMS.debug("AdminAuthenticatePanel: this is the clone subsystem"); 
            String uid = HttpInput.getUID(request, "uid");
            if (uid == null) {
                context.put("errorString", "Uid is empty");
                throw new IOException("Uid is empty");
            }
            context.put("uid", uid);
            String pwd = HttpInput.getPassword(request, "__password");
            config.putString("preop.master.admin.uid", uid);
            config.putString("preop.master.admin.pwd", pwd);
            String host = "";
            int httpsport = -1;
            try {
                host = config.getString("preop.master.hostname");
            } catch (Exception e) {
                CMS.debug("AdminAuthenticatePanel update: "+e.toString());
                context.put("errorString", "Missing hostname for master");
                throw new IOException("Missing hostname");
            }

            try {
                httpsport = config.getInteger("preop.master.httpsadminport");
            } catch (Exception e) {
                CMS.debug("AdminAuthenticatePanel update: "+e.toString());
                context.put("errorString", "Missing port for master");
                throw new IOException("Missing port");
            }

            String list = "";
            try {
                list = config.getString("preop.cert.list", "");
            } catch (Exception e) {
            }

            StringBuffer c1 = new StringBuffer();
            StringBuffer s1 = new StringBuffer();

            StringTokenizer tok = new StringTokenizer(list, ",");
            while (tok.hasMoreTokens()) {
                String t1 = tok.nextToken();
                c1.append(",");
                c1.append("cloning.");
                c1.append(t1);
                c1.append(".nickname,");
                c1.append("cloning.");
                c1.append(t1);
                c1.append(".dn,");
                c1.append("cloning.");
                c1.append(t1);
                c1.append(".keytype,");
                c1.append("cloning.");
                c1.append(t1);
                c1.append(".keyalgorithm,");
                c1.append("cloning.");
                c1.append(t1);
                c1.append(".privkey.id,");
                c1.append("cloning.");
                c1.append(t1);
                c1.append(".pubkey.exponent,");
                c1.append("cloning.");
                c1.append(t1);
                c1.append(".pubkey.modulus,");
                c1.append("cloning.");
                c1.append(t1);
                c1.append(".pubkey.encoded");
                
                if (s1.length()!=0)
                    s1.append(",");
 
                s1.append(cstype);
                s1.append(".");
                s1.append(t1);
            }

            if (!cstype.equals("ca")) {
                c1.append(",preop.ca.hostname,preop.ca.httpport,preop.ca.httpsport,preop.ca.list,preop.ca.pkcs7,preop.ca.type");
            }
            s1.append(",internaldb,internaldb.ldapauth,internaldb.ldapconn");
            String content =
                    "uid=" + uid
                    + "&pwd=" + pwd
                    + "&op=get&names=cloning.module.token,instanceId,"
                    + "internaldb.ldapauth.password,internaldb.replication.password"
                    + c1.toString() + "&substores=" + s1.toString();

            boolean success = updateConfigEntries(host, httpsport, true,
              "/"+cstype+"/admin/"+cstype+"/getConfigEntries", content, config,
              response);

            try {
                config.commit(false);
            } catch (Exception ee) {
            }

            if (!success) {
                context.put("errorString", "Failed to get configuration entries from the master");
                throw new IOException("Failed to get configuration entries from the master");
            } else {
                boolean cloneReady = isCertdbCloned(request, context);
                if (!cloneReady) {
                    CMS.debug("AdminAuthenticatePanel update: clone does not have all the certificates.");
                    context.put("errorString", "Make sure you have copied the certificate database over to the clone");
                    throw new IOException("Clone is not ready");
                }
            }
        } else {
            CMS.debug("AdminAuthentication update: no authentication is required.");
        }

        config.putBoolean("preop.AdminAuthenticate.done", true);
        try {
            config.commit(false);
        } catch (EBaseException e) {
        }
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
        HttpServletResponse response,
        Context context)
    {
        context.put("title", "Admin Authentication");
        context.put("password", "");
        context.put("panel", "admin/console/config/adminauthenticatepanel.vm");
    }

    private boolean isCertdbCloned(HttpServletRequest request,
      Context context) {
        IConfigStore config = CMS.getConfigStore();
        String certList = "";
        try {
            CryptoManager cm = CryptoManager.getInstance();
            certList = config.getString("preop.cert.list");
            StringTokenizer st = new StringTokenizer(certList, ",");
            while (st.hasMoreTokens()) {
                String token = st.nextToken();
                String tokenname = config.getString("preop.module.token", "");
                CryptoToken tok = cm.getTokenByName(tokenname);
                CryptoStore store = tok.getCryptoStore();
                String name1 = "preop.master."+token+".nickname";
                String nickname = config.getString(name1, "");
                if (!tokenname.equals("Internal Key Storage Token") &&
                  !tokenname.equals("internal"))
                    nickname = tokenname+":"+nickname;

                CMS.debug("AdminAuthenticatePanel isCertdbCloned: "+nickname);
                X509Certificate cert = cm.findCertByNickname(nickname);
                if (cert == null)
                    return false;
            }
        } catch (Exception e) {
            context.put("errorString", "Check your CS.cfg for cloning");
            return false;
        }

        return true;
    }
}
