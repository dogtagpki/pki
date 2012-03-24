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
import java.net.URL;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.context.Context;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.certsrv.util.HttpInput;
import com.netscape.cms.servlet.wizard.WizardServlet;

public class CreateSubsystemPanel extends WizardPanelBase {

    public CreateSubsystemPanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Subsystem Selection");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("Subsystem Type");
        setId(id);
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putString("preop.subsystem.select", "");
        cs.putString("subsystem.select", "");
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.subsystem.select", "");
            if (s == null || s.equals("")) {
                return false;
            } else {
                return true;
            }
        } catch (EBaseException e) {
        }
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
        context.put("title", "Subsystem Type");
        IConfigStore config = CMS.getConfigStore();
        String session_id = request.getParameter("session_id");
        if (session_id != null) {
            CMS.debug("CreateSubsystemPanel setting session id.");
            CMS.setConfigSDSessionId(session_id);
        }

        String errorString = "";

        if (isPanelDone()) {
            try {
                String s = config.getString("preop.subsystem.select");

                if (s.equals("new")) {
                    context.put("check_newsubsystem", "checked");
                    context.put("check_clonesubsystem", "");
                } else if (s.equals("clone")) {
                    context.put("check_newsubsystem", "");
                    context.put("check_clonesubsystem", "checked");
                }
                context.put("subsystemName",
                        config.getString("preop.subsystem.name"));
            } catch (Exception e) {
                CMS.debug(e.toString());
            }
        } else {
            context.put("check_newsubsystem", "checked");
            context.put("check_clonesubsystem", "");
            try {
                context.put("subsystemName",
                        config.getString("preop.system.fullname"));
            } catch (Exception e) {
                CMS.debug(e.toString());
            }
        }

        String cstype = "";

        try {
            cstype = config.getString("cs.type", "");
            context.put("cstype", cstype);
            context.put("wizardname", config.getString("preop.wizard.name"));
            context.put("systemname", config.getString("preop.system.name"));
            context.put("fullsystemname", config.getString("preop.system.fullname"));
            context.put("machineName", config.getString("machineName"));
            context.put("http_port", CMS.getEENonSSLPort());
            context.put("https_agent_port", CMS.getAgentPort());
            context.put("https_ee_port", CMS.getEESSLPort());
            context.put("https_admin_port", CMS.getAdminPort());
        } catch (EBaseException e) {
        }

        Vector<String> v = getUrlListFromSecurityDomain(config, cstype, "SecurePort");

        StringBuffer list = new StringBuffer();
        int size = v.size();
        for (int i = 0; i < size; i++) {
            if (i == size - 1) {
                list.append(v.elementAt(i));
            } else {
                list.append(v.elementAt(i));
                list.append(",");
            }
        }

        try {
            config.putString("preop.master.list", list.toString());
            config.commit(false);
        } catch (Exception e) {
            errorString = "Internal error, cs.type is missing from CS.cfg";
        }

        if (list.length() == 0)
            context.put("disableClone", "true");

        context.put("panel", "admin/console/config/createsubsystempanel.vm");
        context.put("errorString", errorString);
        context.put("urls", v);
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
        String errorString = "";
        IConfigStore config = CMS.getConfigStore();
        String select = HttpInput.getID(request, "choice");

        if (select == null) {
            CMS.debug("CreateSubsystemPanel: choice not found");
            context.put("updateStatus", "failure");
            throw new IOException("choice not found");
        }

        config.putString("preop.subsystem.name",
                HttpInput.getName(request, "subsystemName"));
        if (select.equals("newsubsystem")) {
            config.putString("preop.subsystem.select", "new");
            config.putString("subsystem.select", "New");
        } else if (select.equals("clonesubsystem")) {
            String cstype = "";
            try {
                cstype = config.getString("cs.type", "");
            } catch (Exception e) {
            }

            cstype = toLowerCaseSubsystemType(cstype);

            config.putString("preop.subsystem.select", "clone");
            config.putString("subsystem.select", "Clone");

            String lists = "";
            try {
                lists = config.getString("preop.cert.list", "");
            } catch (Exception ee) {
            }

            StringTokenizer t = new StringTokenizer(lists, ",");
            while (t.hasMoreTokens()) {
                String tag = t.nextToken();
                if (tag.equals("sslserver"))
                    config.putBoolean(PCERT_PREFIX + tag + ".enable", true);
                else
                    config.putBoolean(PCERT_PREFIX + tag + ".enable", false);
            }

            // get the master CA
            String index = request.getParameter("urls");
            String url = "";

            try {
                int x = Integer.parseInt(index);
                String list = config.getString("preop.master.list", "");
                StringTokenizer tokenizer = new StringTokenizer(list, ",");
                int counter = 0;

                while (tokenizer.hasMoreTokens()) {
                    url = tokenizer.nextToken();
                    if (counter == x) {
                        break;
                    }
                    counter++;
                }
            } catch (Exception e) {
            }

            url = url.substring(url.indexOf("http"));

            URL u = new URL(url);
            String host = u.getHost();
            int https_ee_port = u.getPort();

            String https_admin_port = getSecurityDomainAdminPort(config,
                                                                  host,
                                                                  String.valueOf(https_ee_port),
                                                                  cstype);

            config.putString("preop.master.hostname", host);
            config.putInteger("preop.master.httpsport", https_ee_port);
            config.putString("preop.master.httpsadminport", https_admin_port);

            ConfigCertApprovalCallback certApprovalCallback = new ConfigCertApprovalCallback();
            if (cstype.equals("ca")) {
                updateCertChainUsingSecureEEPort(config, "clone", host, https_ee_port,
                                 true, context, certApprovalCallback);
            }

            getTokenInfo(config, cstype, host, https_ee_port, true, context,
                    certApprovalCallback);
        } else {
            CMS.debug("CreateSubsystemPanel: invalid choice " + select);
            errorString = "Invalid choice";
            context.put("updateStatus", "failure");
            throw new IOException("invalid choice " + select);
        }

        try {
            config.commit(false);
        } catch (EBaseException e) {
        }

        context.put("errorString", errorString);
        context.put("updateStatus", "success");
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("title", "Subsystem Type");
        context.put("panel", "admin/console/config/createsubsystempanel.vm");
    }
}
