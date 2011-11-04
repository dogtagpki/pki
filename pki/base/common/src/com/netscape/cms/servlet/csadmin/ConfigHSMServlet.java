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


import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.Template;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.context.Context;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkcs11.PK11Module;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.cmsutil.crypto.Module;


public class ConfigHSMServlet extends ConfigBaseServlet {
    private CryptoManager mCryptoManager = null;
    private Vector mSupportedModules = null;
    private Vector mOtherModules = null;
    private String mDefaultTok = null;
    private Hashtable mCurrModTable = new Hashtable();

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }

    public void loadCurrModTable() {
        try {
            // getting existing modules
            mCryptoManager = CryptoManager.getInstance();
            Enumeration modules = mCryptoManager.getModules();

            while (modules.hasMoreElements()) {
                PK11Module mod = (PK11Module) modules.nextElement();

                CMS.debug("ConfigHSMServlet: got module " + mod.getName());
                mCurrModTable.put(mod.getName(), mod);
            } // while
        } catch (Exception e) {
            CMS.debug(
                    "ConfigHSMServlet: Exception caught in loadCurrModTable: "
                            + e.toString());
            System.err.println("Exception caught: " + e.toString());
        }
    }

    /*
     * Modules not listed as supported modules
     */
    public void loadOtherModules() {
        Enumeration m = mCurrModTable.elements();

        mOtherModules = new Vector();
        while (m.hasMoreElements()) {
            PK11Module mod = (PK11Module) m.nextElement();
            Enumeration s = mSupportedModules.elements();
            boolean found = false;

            while (s.hasMoreElements()) {
                Module sm = (Module) s.nextElement();

                if (mod.getName().equals(sm.getCommonName())) {
                    found = true;
                    break;
                } else {
                    found = false;
                }
            }// while
            if (!found) {
                // unsupported, use common name as user friendly name
                Module module = new Module(mod.getName(), mod.getName());

                loadModTokens(module, mod);
                module.setFound(true);
                mOtherModules.addElement((Object) module);
                break;
            }
        }// while
    }

    /*
     * find all tokens belonging to a module and load the Module
     */
    public void loadModTokens(Module module, PK11Module mod) {
        Enumeration tokens = mod.getTokens();

        while (tokens.hasMoreElements()) {
            try {
                CryptoToken token = (CryptoToken) tokens.nextElement();

                CMS.debug("ConfigHSMServlet: token nick name=" + token.getName());
                CMS.debug(
                        "ConfigHSMServlet: token logged in?"
                                + token.isLoggedIn());
                CMS.debug(
                        "ConfigHSMServlet: token is present?"
                                + token.isPresent());
                if (!token.getName().equals("Internal Crypto Services Token")) {
                    module.addToken(token);
                } else {
                    CMS.debug(
                            "ConfigHSMServlet: token " + token.getName()
                            + " not to be added");
                }
			    
            } catch (TokenException ex) {
                CMS.debug("ConfigHSMServlet:" + ex.toString());
            }
        }
    }

    /*
     * Modules unsupported by the system will not be included
     */
    public void loadSupportedModules() {

        // getting supported security modules
        // a Vectgor of Modules
        mSupportedModules = new Vector();
        // read from conf store all supported modules
        try {
            int count = CMS.getConfigStore().getInteger(
                    "preop.configModules.count");

            CMS.debug("ConfigHSMServlet: supported modules count= " + count);
            for (int i = 0; i < count; i++) {
                String cn = CMS.getConfigStore().getString(
                        "preop.configModules.module" + i + ".commonName");
                String pn = CMS.getConfigStore().getString(
                        "preop.configModules.module" + i + ".userFriendlyName");
                String img = CMS.getConfigStore().getString(
                        "preop.configModules.module" + i + ".imagePath");

                if ((cn == null) || (cn.equals(""))) {
                    break;
                }
		
                CMS.debug("ConfigHSMServlet: got from config module: " + cn);
                // create a Module object
                Module module = new Module(cn, pn, img);
		
                if (mCurrModTable.containsKey(cn)) {
                    CMS.debug("ConfigHSMServlet: module found: " + cn);
                    module.setFound(true);
                    // add token info to module vector
                    PK11Module m = (PK11Module) mCurrModTable.get(cn);

                    loadModTokens(module, m);
                }
		
                CMS.debug("ConfigHSMServlet: adding module " + cn);
                // add module to set
                if (!mSupportedModules.contains(module)) {
                    mSupportedModules.addElement((Object) module);
                }
            }// for

        } catch (Exception e) {
            CMS.debug(
                    "ConfigHSMServlet: Exception caught in loadSupportedModules(): "
                            + e.toString());
            System.err.println("Exception caught: " + e.toString());
        }
    }

    public boolean isDisplayMode(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        String choice = request.getParameter("choice");

        if (choice == null) {
            return true;
        } else {
            return false;
        }
    }

    public boolean isPanelModified(IConfigStore cs) {
        String modified = "";

        try {
            modified = cs.getString("preop.configModules.modified", "");
        } catch (Exception e) {
            return false;
        }

        if (modified.equals("true")) {
            return true;
        } else {
            return false;
        }
    }

    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        CMS.debug("ConfigHSMServlet: in display()");

        loadCurrModTable();
        loadSupportedModules();
        loadOtherModules();
        // getting default token selection
        try {
            mDefaultTok = CMS.getConfigStore().getString(
                    "preop.configModules.defaultTok",
                    "Internal Key Storage Token");
        } catch (Exception e) {
            CMS.debug("ConfigHSMServlet: Exception caught: " + e.toString());
            System.err.println("Exception caught: " + e.toString());
        }
        if (mSupportedModules == null) {
            CMS.debug("ConfigHSMServlet: mSupportedModules not loaded");
        } else {
            CMS.debug("ConfigHSMServlet: mSupportedModules loaded");
        }

        context.put("status", "display");
        context.put("oms", mOtherModules);
        context.put("sms", mSupportedModules);
        context.put("defTok", mDefaultTok);
    }

    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        IConfigStore cs = CMS.getConfigStore();

        CMS.debug("ConfigHSMServlet: in update()");

        if (mSupportedModules == null) {
            CMS.debug("ConfigHSMServlet: mSupportedModules not loaded");
        } else {
            CMS.debug("ConfigHSMServlet: mSupportedModules loaded");
        }

        String select = request.getParameter("choice");

        if (select == null) {
            CMS.debug("ConfigHSMServlet: choice not found");
            // throw new IOException("choice not found");
        }

        try {
            CMS.debug("ConfigHSMServlet: choice =" + select);
            cs.putString("preop.configModules.defaultTok", select);
            cs.commit(false);
        } catch (Exception e) {
            CMS.debug("ConfigHSMServlet: Exception caught: " + e.toString());
            System.err.println("Exception caught: " + e.toString());
        }
        context.put("status", "update");
        context.put("error", "");

    }

    public Template getTemplate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        try {
            return Velocity.getTemplate("admin/console/config/config_hsm.vm");
        } catch (Exception e) {}
        return null;
    }
}

