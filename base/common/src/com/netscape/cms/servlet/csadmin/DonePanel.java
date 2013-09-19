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
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.velocity.context.Context;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.cms.servlet.wizard.WizardServlet;
import com.netscape.cmsutil.util.Utils;

public class DonePanel extends WizardPanelBase {

    public static final BigInteger BIG_ZERO = new BigInteger("0");
    public static final Long MINUS_ONE = Long.valueOf(-1);
    public static final String RESTART_SERVER_AFTER_CONFIGURATION =
            "restart_server_after_configuration";
    public static final String PKI_SECURITY_DOMAIN = "pki_security_domain";

    public DonePanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Done");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("Done");
        setId(id);
    }

    public boolean hasSubPanel() {
        return false;
    }

    public void cleanUp() throws IOException {
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();

        /* XXX */

        return set;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request, HttpServletResponse response, Context context) {
        CMS.debug("DonePanel: display()");

        // update session id
        String session_id = request.getParameter("session_id");
        if (session_id != null) {
            CMS.debug("NamePanel setting session id.");
            CMS.setConfigSDSessionId(session_id);
        }

        IConfigStore cs = CMS.getConfigStore();

        String select = "";
        String type = "";
        String instanceId = "";
        String instanceRoot = "";
        String systemdService = "";
        String ca_host = "";
        String sdtype = "";
        int state = 0;
        try {
            type = cs.getString("cs.type", "");
            instanceId = cs.getString("instanceId");
            instanceRoot = cs.getString("instanceRoot");
            select = cs.getString("preop.subsystem.select", "");
            systemdService = cs.getString("pkicreate.systemd.servicename", "");
            ca_host = cs.getString("preop.ca.hostname", "");
            sdtype = cs.getString("securitydomain.select", "");
            state = cs.getInteger("cs.state");
        } catch (Exception e) {
        }

        String initDaemon = "";
        if (type.equals("CA")) {
            initDaemon = "pki-cad";
        } else if (type.equals("KRA")) {
            initDaemon = "pki-krad";
        } else if (type.equals("OCSP")) {
            initDaemon = "pki-ocspd";
        } else if (type.equals("TKS")) {
            initDaemon = "pki-tksd";
        }
        String os = System.getProperty("os.name");
        if (os.equalsIgnoreCase("Linux")) {
            if (!systemdService.equals("")) {
                context.put("initCommand", "/bin/systemctl");
                context.put("instanceId", systemdService);
            } else {
                context.put("initCommand", "/sbin/service " + initDaemon);
                context.put("instanceId", instanceId);
            }
        } else {
            /* default case:  e. g. - ( os.equalsIgnoreCase( "SunOS" ) */
            context.put("initCommand", "/etc/init.d/" + initDaemon);
            context.put("instanceId", instanceId);
        }
        context.put("title", "Done");
        context.put("panel", "admin/console/config/donepanel.vm");
        context.put("host", CMS.getAdminHost());
        context.put("port", CMS.getAdminPort());
        context.put("systemType", type.toLowerCase());

        if (state == 1) {
            context.put("csstate", "1");
            return;
        } else
            context.put("csstate", "0");

        if (ca_host.equals(""))
            context.put("externalCA", "true");
        else
            context.put("externalCA", "false");

        // Create or update security domain

        try {
            if (sdtype.equals("new")) {
                ConfigurationUtils.createSecurityDomain();
            } else { //existing domain
                ConfigurationUtils.updateSecurityDomain();
            }

            cs.putString("service.securityDomainPort", CMS.getAgentPort());
            cs.putString("securitydomain.store", "ldap");
            cs.commit(false);
        } catch (Exception e) {
            CMS.debug("DonePanel - update(): Error while updating security domain: " + e);
            e.printStackTrace();
        }

        // push connector information to the CA
        try {
            if (type.equals("KRA") && !ca_host.equals("")) {
                ConfigurationUtils.updateConnectorInfo(CMS.getAgentHost(), CMS.getAgentPort());
                ConfigurationUtils.setupClientAuthUser();
            }
        } catch (Exception e) {
            context.put("info", "Failed to update connector information. "+e.getMessage());
            CMS.debug("DonePanel - update(): Error while pushing KRA connectot information to the CA: " + e);
            e.printStackTrace();
        }

        // import the CA certificate into the OCSP
        // configure the CRL Publishing to OCSP in CA
        try {
            if (type.equals("OCSP") && !ca_host.equals("")) {
                CMS.reinit(IOCSPAuthority.ID);
                ConfigurationUtils.importCACertToOCSP();
                ConfigurationUtils.updateOCSPConfig();
                ConfigurationUtils.setupClientAuthUser();
            }
        } catch (Exception e) {
            CMS.debug("DonePanel - update(): Error while configuring OCSP publishing on the CA: " + e);
            e.printStackTrace();
        }

        try {
            if (!select.equals("clone")) {
                if (type.equals("CA") || type.equals("KRA")) {
                    ConfigurationUtils.updateNextRanges();

                }
            }
        } catch (Exception e) {
            CMS.debug("DonePanel - update(): Error while updating serial number next ranges: " + e);
            e.printStackTrace();
        }

        try {
            if (select.equals("clone") && type.equalsIgnoreCase("CA") && ConfigurationUtils.isSDHostDomainMaster(cs)) {
                // cloning a domain master CA, the clone is also master of its domain
                CMS.debug("Cloning a domain master");
                cs.putString("securitydomain.host", CMS.getEESSLHost());
                cs.putString("securitydomain.httpport", CMS.getEENonSSLPort());
                cs.putString("securitydomain.httpsadminport", CMS.getAdminPort());
                cs.putString("securitydomain.httpsagentport", CMS.getAgentPort());
                cs.putString("securitydomain.httpseeport", CMS.getEESSLPort());
                cs.putString("securitydomain.select", "new");
            }
        } catch (Exception e) {
            CMS.debug("DonePanel - update(): Error in determining if security domain host is a master CA: " + e);
            e.printStackTrace();
        }

        try {
            ConfigurationUtils.setupDBUser();
        } catch (Exception e) {
            e.printStackTrace();
            CMS.debug("DonePanel - update(): Unable to create or update dbuser" + e);
        }

        if (type.equals("TPS")) {
            try {
                String adminUID = cs.getString("preop.admin.uid", "tpsadmin");
                ConfigurationUtils.addProfilesToTPSUser(adminUID);

                String sd_admin_port = cs.getString("securitydomain.httpsadminport");
                String sd_host = cs.getString("securitydomain.host");
                URI secdomainURI = new URI("https://" + sd_host + ":" + sd_admin_port);

                // register TPS with CA
                URI caURI = new URI(cs.getString("preop.cainfo.select"));
                ConfigurationUtils.registerUser(secdomainURI, caURI, "ca");

                // register TPS with TKS
                URI tksURI = new URI(cs.getString("preop.tksinfo.select"));
                ConfigurationUtils.registerUser(secdomainURI, tksURI, "tks");

                String keyGen = cs.getString("conn.tks1.serverKeygen", "false");
                if (keyGen.equalsIgnoreCase("true")) {
                    URI kraURI = new URI(cs.getString("preop.krainfo.select"));
                    ConfigurationUtils.registerUser(secdomainURI, kraURI, "kra");
                    String transportCert = ConfigurationUtils.getTransportCert(secdomainURI, kraURI);
                    ConfigurationUtils.exportTransportCert(secdomainURI, tksURI, transportCert);
                }
            } catch (URISyntaxException e) {
                e.printStackTrace();
                CMS.debug("Invalid URI for CA, TKS or KRA: " + e);
            } catch (Exception e) {
                e.printStackTrace();
                CMS.debug("Errors in registering TPS to CA, TKS or KRA: " + e);
            }
        }

        cs.putInteger("cs.state", 1);
        try {
            ConfigurationUtils.removePreopConfigEntries();
        } catch (Exception e) {
            CMS.debug("DonePanel - update(): Caught exception saving preop variables: " + e);
        }

        // Create an empty file that designates the fact that although
        // this server instance has been configured, it has NOT yet
        // been restarted!
        String restart_server = instanceRoot + "/conf/"
                + RESTART_SERVER_AFTER_CONFIGURATION;
        if (!Utils.isNT()) {
            Utils.exec("touch " + restart_server);
            Utils.exec("chmod 00660 " + restart_server);
        }

        context.put("csstate", "1");
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
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {/* This should never be called */
    }
}
