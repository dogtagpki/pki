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

        try {
            String session_id = request.getParameter("session_id");
            if (session_id != null) {
                CMS.debug("CreateSubsystemPanel setting session id.");
                CMS.setConfigSDSessionId(session_id);
            }

            if (isPanelDone()) {
                String s = config.getString("preop.subsystem.select");
                if (s.equals("new")) {
                    context.put("check_newsubsystem", "checked");
                    context.put("check_clonesubsystem", "");
                } else if (s.equals("clone")) {
                    context.put("check_newsubsystem", "");
                    context.put("check_clonesubsystem", "checked");
                }
                context.put("subsystemName", config.getString("preop.subsystem.name"));
            } else {
                context.put("check_newsubsystem", "checked");
                context.put("check_clonesubsystem", "");
                context.put("subsystemName", config.getString("preop.system.fullname"));
            }

            String cstype = config.getString("cs.type", "");
            context.put("cstype", cstype);
            context.put("wizardname", config.getString("preop.wizard.name"));
            context.put("systemname", config.getString("preop.system.name"));
            context.put("fullsystemname", config.getString("preop.system.fullname"));
            context.put("machineName", config.getString("machineName"));
            context.put("http_port", CMS.getEENonSSLPort());
            context.put("https_agent_port", CMS.getAgentPort());
            context.put("https_ee_port", CMS.getEESSLPort());
            context.put("https_admin_port", CMS.getAdminPort());

            String domainType = config.getString("preop.securitydomain.select");
            Vector<String> v = null;
            if (!domainType.equals("new")) {
                try {
                    v = ConfigurationUtils.getUrlListFromSecurityDomain(config, cstype, "SecurePort");
                } catch (Exception e) {
                    // note: this is OK for a new master ca in a new domain
                    CMS.debug("Exception thrown when obtaining URL List from security domain:" + e);
                    e.printStackTrace();
                }
            }

            if (v == null) {
                v = new Vector<String>();
            }

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

            config.putString("preop.master.list", list.toString());
            config.commit(false);

            if (list.length() == 0)
                context.put("disableClone", "true");

            context.put("panel", "admin/console/config/createsubsystempanel.vm");
            context.put("urls", v);
            context.put("errorString", "");
        } catch (Exception e) {
            e.printStackTrace();
            context.put("errorString", e.toString());
            CMS.debug("CreateSubsystemPanel: Exception thrown: " + e);
        }
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
        String select = HttpInput.getID(request, "choice");

        if (select == null) {
            CMS.debug("CreateSubsystemPanel: choice not found");
            context.put("updateStatus", "failure");
            throw new IOException("choice not found");
        }

        try {
            String cstype = config.getString("cs.type", "");
            config.putString("preop.subsystem.name", HttpInput.getName(request, "subsystemName"));

            if (select.equals("newsubsystem")) {
                config.putString("preop.subsystem.select", "new");
                config.putString("subsystem.select", "New");
            } else if (select.equals("clonesubsystem")) {
                config.putString("preop.subsystem.select", "clone");
                config.putString("subsystem.select", "Clone");

                String lists = config.getString("preop.cert.list", "");
                StringTokenizer t = new StringTokenizer(lists, ",");
                while (t.hasMoreTokens()) {
                    String tag = t.nextToken();
                    if (tag.equals("sslserver"))
                        config.putBoolean(PCERT_PREFIX + tag + ".enable", true);
                    else
                        config.putBoolean(PCERT_PREFIX + tag + ".enable", false);
                }

                // get the masterURL
                String index = request.getParameter("urls");
                String url = "";

                int x = Integer.parseInt(index);
                String list = config.getString("preop.master.list", "");
                StringTokenizer tokenizer = new StringTokenizer(list, ",");
                int counter = 0;

                while (tokenizer.hasMoreTokens()) {
                    url = tokenizer.nextToken();
                    if (counter == x) break;
                    counter++;
                }

                url = url.substring(url.indexOf("http"));

                URL u = new URL(url);
                String host = u.getHost();
                int https_ee_port = u.getPort();

                String domainXML = config.getString("preop.domainXML");

                // check URI and update preop.master port entries
                boolean validUri = ConfigurationUtils.isValidCloneURI(domainXML, host, https_ee_port);
                if (!validUri) {
                    throw new IOException("Invalid clone URI provided.  Does not match the available subsystems in " +
                            "the security domain");
                }
                if (cstype.equals("CA")) {
                    int https_admin_port = ConfigurationUtils.getPortFromSecurityDomain(domainXML,
                                               host, https_ee_port, "CA", "SecurePort", "SecureAdminPort");

                    ConfigurationUtils.importCertChain(host, https_admin_port, "/ca/admin/ca/getCertChain", "clone");
                }
            } else {
                CMS.debug("CreateSubsystemPanel: invalid choice " + select);
                context.put("updateStatus", "failure");
                throw new IOException("invalid choice " + select);
            }

            config.commit(false);
        } catch (Exception e) {
            CMS.debug("CreateSubsystemPanel: Exception thrown : " + e);
            context.put("errorString", e.toString());
            context.put("updateStatus", "failure");
            throw new IOException(e);
        }

        context.put("updateStatus", "success");
    }

    /**
     * If validate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("title", "Subsystem Type");
        context.put("panel", "admin/console/config/createsubsystempanel.vm");
    }
}
