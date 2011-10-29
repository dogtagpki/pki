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
import javax.servlet.http.*;
import javax.servlet.*;

import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.property.*;
import com.netscape.cmsutil.crypto.*;
import java.util.*;
import java.io.*;
import org.mozilla.jss.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.pkcs11.*;
import org.mozilla.jss.util.Password;
import org.mozilla.jss.util.PasswordCallback;
import org.mozilla.jss.util.IncorrectPasswordException;
import com.netscape.cmsutil.password.*;

import com.netscape.cms.servlet.wizard.*;

public class ConfigHSMLoginPanel extends WizardPanelBase {
    private CryptoManager mCryptoManager = null;
    private String mPwdFilePath = "";

    public ConfigHSMLoginPanel() {}

    public void init(ServletConfig config, int panelno) throws ServletException {
        try {
            mCryptoManager = CryptoManager.getInstance();
            mPwdFilePath = CMS.getConfigStore().getString(
                    "passwordFile");
        } catch (Exception e) {
            CMS.debug("ConfigHSMLoginPanel: " + e.toString());
        }
        setPanelNo(panelno);
        setName("ConfigHSMLogin");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id) throws ServletException {
        try {
            mCryptoManager = CryptoManager.getInstance();
            mPwdFilePath = CMS.getConfigStore().getString(
                    "passwordFile");
        } catch (Exception e) {
            CMS.debug("ConfigHSMLoginPanel: " + e.toString());
        }
        setPanelNo(panelno);
        setName("ConfigHSMLogin");
        setId(id);
    }

    public void cleanUp() throws IOException {
    }

    public boolean isPanelDone() {
        return true;
    }

    public boolean isSubPanel() {
        return true;
    }

    public boolean isLoopbackPanel() {
        return true;
    }

    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        CMS.debug("ConfigHSMLoginPanel: in display()");
        context.put("title", "Security Module Login");

        // get token selected to be logged in
        String tokName = null;
        try {
            tokName = HttpInput.getTokenName(request, "SecToken");
        } catch (IOException e) {
        }

        if (tokName != null) {
            CMS.debug("ConfigHSMLoginPanel: selected token name= " + tokName);
        } else {
            CMS.debug("ConfigHSMLoginPanel: missing SecToken name");
            context.put("error", "noTokenName");
            context.put("panel", "admin/console/config/config_hsmloginpanel.vm");
            return;
        }
        CryptoToken token = null;

        try {
            token = mCryptoManager.getTokenByName(tokName);
        } catch (Exception e) {
            CMS.debug(
                    "ConfigHSMLoginPanel: getTokenByName() failed: "
                            + e.toString());
            context.put("error", "tokenNotFound:" + tokName);
            context.put("panel", "admin/console/config/config_hsmloginpanel.vm");
            return;
        }
        // first see if password in password file, try to login
        PlainPasswordReader pr = new PlainPasswordReader();

        try {
            pr.init(mPwdFilePath);
        } catch (Exception e) {
            // is ok to not have it
            CMS.debug("ConfigHSMLoginPanel: passwrd file path: " + e.toString());
        }
        CMS.debug("ConfigHSMLoginPanel: checking if passwd in cache");
        String tokPwd = pr.getPassword("hardware-"+tokName);

        boolean loggedIn = false;

        if (tokPwd == null) {
            CMS.debug("ConfigHSMLoginPanel: passwd not in cache");
        } else {
            loggedIn = loginToken(token, tokPwd, context);
        }

        if (!loggedIn) {
            context.put("status", "display");
        }
        context.put("panel", "admin/console/config/config_hsmloginpanel.vm");
        context.put("SecToken", tokName);
    }

    // if logged in successfully, returns true
    private boolean loginToken(CryptoToken token, String tokPwd, Context context) {
        boolean rv = true;
        Password password = null;

        password = new Password(tokPwd.toCharArray());

        if (password != null) {
            try {
                if (token.passwordIsInitialized()) {
                    CMS.debug(
                            "ConfigHSMLoginPanel: loginToken():token password is initialized");
                    if (!token.isLoggedIn()) {
                        CMS.debug(
                                "ConfigHSMLoginPanel: loginToken():Token is not logged in, try it");
                        token.login(password);
                        context.put("status", "justLoggedIn");
                    } else {
                        CMS.debug(
                                "ConfigHSMLoginPanel:Token has already logged on");
                        context.put("status", "alreadyLoggedIn");
                    }
                } else {
                    CMS.debug(
                            "ConfigHSMLoginPanel: loginToken():Token password not initialized");
                    context.put("status", "tokenPasswordNotInitialized");
                    rv = false;
                }
		
            } catch (IncorrectPasswordException e) {
                context.put("status", "incorrectPassword");
                context.put("errorString", e.toString());
                CMS.debug("ConfigHSMLoginPanel: loginToken():" + e.toString());
                rv = false;
            } catch (Exception e) {
                CMS.debug("ConfigHSMLoginPanel: loginToken():" + e.toString());
                context.put("errorString", e.toString());
                rv = false;
            }
        } else { // no password in password file, get from user
            CMS.debug(
                    "ConfigHSMLoginPanel:  loginToken():no password in cache, getting from user");
            rv = false;
        }
        return rv;
    }

    // XXX how do you do this?
    public PropertySet getUsage() {
        PropertySet set = new PropertySet();
                                                                                
        Descriptor choiceDesc = new Descriptor(IDescriptor.CHOICE, "", "", null); /* no default parameters */

        set.add(
                "choice", choiceDesc);
                                                                                
        return set;
    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
    }

    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        IConfigStore cs = CMS.getConfigStore();
        String select = "";
        try {
            select = cs.getString("preop.subsystem.select", "");
        } catch (Exception e) {
        }
     
//        if (select.equals("clone"))
 //           return;
      
        CMS.debug("ConfigHSMLoginPanel: in update()");

        String uTokName = null;
        String uPasswd = null;
        try {
            uTokName = HttpInput.getTokenName(request, "uTokName");
            uPasswd = HttpInput.getPassword(request, "__uPasswd");
        } catch (Exception e) {
        }
     
        if (uPasswd == null) {
            CMS.debug("ConfigHSMLoginPanel: password not found");
            context.put("error", "no password");
            context.put("panel", "admin/console/config/config_hsmloginpanel.vm");
            context.put("updateStatus", "no password");
            return;
        } else {
            CMS.debug("ConfigHSMLoginPanel: got password");

            CryptoToken token = null;

            try {
                token = mCryptoManager.getTokenByName(uTokName);
            } catch (Exception e) {
                CMS.debug(
                        "ConfigHSMLoginPanel: getTokenByName() failed: "
                                + e.toString());
                context.put("error", "tokenNotFound:" + uTokName);
            }

            try {
                if (loginToken(token, uPasswd, context) == false) {
                    CMS.debug(
                            "ConfigHSMLoginPanel:loginToken failed for "
                                    + uTokName);
                    context.put("error", "tokenLoginFailed");
                    context.put("updateStatus", "login failed");
                    context.put("panel",
                            "admin/console/config/config_hsmloginpanel.vm");
                    return;
                }
                CMS.debug(
                        "ConfigHSMLoginPanel: update(): just logged in successfully");
                PlainPasswordWriter pw = new PlainPasswordWriter();

                pw.init(mPwdFilePath);
                pw.putPassword("hardware-"+uTokName, uPasswd);
                pw.commit();

            } catch (FileNotFoundException e) {
                CMS.debug(
                        "ConfigHSMLoginPanel: update(): Exception caught: "
                                + e.toString() + " writing to "+ mPwdFilePath);
                CMS.debug(
                        "ConfigHSMLoginPanel: update(): password not written to cache");
                System.err.println("Exception caught: " + e.toString());
                context.put("error", "Exception:" + e.toString());
            } catch (Exception e) {
                CMS.debug(
                        "ConfigHSMLoginPanel: update(): Exception caught: "
                                + e.toString());
                System.err.println("Exception caught: " + e.toString());
                context.put("error", "Exception:" + e.toString());
            }
	    
        } // found password

        context.put("panel", "admin/console/config/config_hsmloginpanel.vm");
        context.put("status", "update");
        context.put("error", "");
        context.put("updateStatus", "success");

    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("title", "Security Module Login");
        context.put("panel", "admin/console/config/config_hsmloginpanel.vm");
    }
}

