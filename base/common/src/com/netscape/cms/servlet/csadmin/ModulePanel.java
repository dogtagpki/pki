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

import java.io.IOException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.context.Context;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.pkcs11.PK11Module;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.certsrv.util.HttpInput;
import com.netscape.cms.servlet.wizard.WizardServlet;
import com.netscape.cmsutil.crypto.Module;

public class ModulePanel extends WizardPanelBase {
    private CryptoManager mCryptoManager = null;
    private Vector<Module> mSupportedModules = null;
    private Vector<Module> mOtherModules = null;
    private Hashtable<String, PK11Module> mCurrModTable = new Hashtable<String, PK11Module>();
    private WizardServlet mServlet = null;

    public ModulePanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Key Store");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("Key Store");
        setId(id);
        mServlet = servlet;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putBoolean("preop.ModulePanel.done", false);
    }

    public void loadCurrModTable() {
        try {
            // getting existing modules
            mCryptoManager = CryptoManager.getInstance();
            @SuppressWarnings("unchecked")
            Enumeration<PK11Module> modules = mCryptoManager.getModules();

            while (modules.hasMoreElements()) {
                PK11Module mod = modules.nextElement();

                CMS.debug("ModulePanel: got module " + mod.getName());
                mCurrModTable.put(mod.getName(), mod);
            } // while
        } catch (Exception e) {
            CMS.debug(
                    "ModulePanel: Exception caught in loadCurrModTable: "
                            + e.toString());
            System.err.println("Exception caught: " + e.toString());
        }
    }

    /*
     * Modules not listed as supported modules
     */
    public void loadOtherModules() {
        Enumeration<PK11Module> m = mCurrModTable.elements();

        mOtherModules = new Vector<Module>();
        while (m.hasMoreElements()) {
            PK11Module mod = m.nextElement();
            Enumeration<Module> s = mSupportedModules.elements();
            boolean found = false;

            while (s.hasMoreElements()) {
                Module sm = s.nextElement();

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
                mOtherModules.addElement(module);
                break;
            }
        }// while
    }

    /*
     * find all tokens belonging to a module and load the Module
     */
    public void loadModTokens(Module module, PK11Module mod) {
        @SuppressWarnings("unchecked")
        Enumeration<CryptoToken> tokens = mod.getTokens();

        while (tokens.hasMoreElements()) {
            try {
                CryptoToken token = tokens.nextElement();

                CMS.debug("ModulePanel: token nick name=" + token.getName());
                CMS.debug("ModulePanel: token logged in?" + token.isLoggedIn());
                CMS.debug("ModulePanel: token is present?" + token.isPresent());
                if (!token.getName().equals("Internal Crypto Services Token") &&
                        !token.getName().equals("NSS Generic Crypto Services")) {
                    module.addToken(token);
                } else {
                    CMS.debug(
                            "ModulePanel: token " + token.getName()
                                    + " not to be added");
                }

            } catch (TokenException ex) {
                CMS.debug("ModulePanel:" + ex.toString());
            }
        }
    }

    /*
     * Modules unsupported by the system will not be included
     */
    public void loadSupportedModules() {

        // getting supported security modules
        // a Vectgor of Modules
        mSupportedModules = new Vector<Module>();
        // read from conf store all supported modules
        try {
            int count = CMS.getConfigStore().getInteger(
                    "preop.configModules.count");

            CMS.debug("ModulePanel: supported modules count= " + count);
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

                CMS.debug("ModulePanel: got from config module: " + cn);
                // create a Module object
                Module module = new Module(cn, pn, img);

                if (mCurrModTable.containsKey(cn)) {
                    CMS.debug("ModulePanel: module found: " + cn);
                    module.setFound(true);
                    // add token info to module vector
                    PK11Module m = mCurrModTable.get(cn);

                    loadModTokens(module, m);
                }

                CMS.debug("ModulePanel: adding module " + cn);
                // add module to set
                if (!mSupportedModules.contains(module)) {
                    mSupportedModules.addElement(module);
                }
            }// for

        } catch (Exception e) {
            CMS.debug(
                    "ModulePanel: Exception caught in loadSupportedModules(): "
                            + e.toString());
            System.err.println("Exception caught: " + e.toString());
        }
    }

    public PropertySet getUsage() {
        // it a token choice.  Available tokens are discovered dynamically so
        // can't be a real CHOICE
        PropertySet set = new PropertySet();

        Descriptor tokenDesc = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* default parameter */
                "module token selection");

        set.add("choice", tokenDesc);

        return set;
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            boolean s = cs.getBoolean("preop.ModulePanel.done",
                    false);

            if (s != true) {
                return false;
            } else {
                return true;
            }
        } catch (EBaseException e) {
        }

        return false;
    }

    public boolean hasSubPanel() {
        return true;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        CMS.debug("ModulePanel: display()");
        context.put("title", "Key Store");

        loadCurrModTable();
        loadSupportedModules();
        loadOtherModules();

        IConfigStore config = CMS.getConfigStore();

        try {
            String s = config.getString("preop.module.token",
                    "Internal Key Storage Token");

            context.put("defTok", s);
        } catch (Exception e) {
            CMS.debug("ModulePanel:" + e.toString());
        }

        context.put("status", "display");
        context.put("oms", mOtherModules);
        context.put("sms", mSupportedModules);
        // context.put("status_token", "None");
        String subpanelno = String.valueOf(getPanelNo() + 1);
        CMS.debug("ModulePanel subpanelno =" + subpanelno);
        context.put("subpanelno", subpanelno);
        context.put("panel", "admin/console/config/modulepanel.vm");
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
        boolean hasErr = false;

        try {
            // get the value of the choice
            String select = HttpInput.getID(request, "choice");

            if (select == null) {
                CMS.debug("ModulePanel: no choice selected");
                hasErr = true;
                throw new IOException("choice not found");
            }

            IConfigStore config = CMS.getConfigStore();
            String oldtokenname = config.getString("preop.module.token", "");
            if (!oldtokenname.equals(select))
                mServlet.cleanUpFromPanel(mServlet.getPanelNo(request));

            if (hasErr == false) {
                config.putString("preop.module.token", select);
                config.putBoolean("preop.ModulePanel.done", true);
            }
            config.commit(false);
            context.put("updateStatus", "success");
        } catch (Exception e) {
            CMS.debug("ModulePanel: Exception caught: " + e.toString());
            System.err.println("Exception caught: " + e.toString());
            context.put("updateStatus", "failure");
        }
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("title", "Security Module");
        context.put("panel", "admin/console/config/modulepanel.vm");
    }
}
