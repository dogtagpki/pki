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
import java.util.Enumeration;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.velocity.context.Context;
import org.xml.sax.SAXException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.certsrv.util.HttpInput;
import com.netscape.cms.servlet.wizard.WizardServlet;

public class NamePanel extends WizardPanelBase {
    private Vector<Cert> mCerts = null;
    private WizardServlet mServlet = null;

    public NamePanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Subject Names");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("Subject Names");
        setId(id);
        mServlet = servlet;
    }

    /**
     * Returns the usage.XXX usage needs to be made dynamic
     */
    public PropertySet getUsage() {
        PropertySet set = new PropertySet();

        Descriptor caDN = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */
                "CA Signing Certificate's DN");

        set.add("caDN", caDN);

        Descriptor sslDN = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */
                "SSL Server Certificate's DN");

        set.add("sslDN", sslDN);

        Descriptor subsystemDN = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */
                "CA Subsystem Certificate's DN");

        set.add("subsystemDN", subsystemDN);

        Descriptor ocspDN = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */
                "OCSP Signing Certificate's DN");

        set.add("ocspDN", ocspDN);

        return set;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        try {
            @SuppressWarnings("unused")
            boolean done = cs.getBoolean("preop.NamePanel.done"); // check for errors
            cs.putBoolean("preop.NamePanel.done", false);
            cs.commit(false);
        } catch (Exception e) {
        }

        String list = "";
        try {
            list = cs.getString("preop.cert.list", "");
        } catch (Exception e) {
        }

        StringTokenizer st = new StringTokenizer(list, ",");
        while (st.hasMoreTokens()) {
            String t = st.nextToken();
            cs.remove("preop.cert." + t + ".done");
        }

        try {
            cs.commit(false);
        } catch (Exception e) {
        }
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            boolean s = cs.getBoolean("preop.NamePanel.done", false);
            if (s != true) {
                return false;
            } else {
                return true;
            }
        } catch (EBaseException e) {
        }

        return false;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        CMS.debug("NamePanel: display()");
        context.put("title", "Subject Names");

        // update session id
        String session_id = request.getParameter("session_id");
        if (session_id != null) {
            CMS.debug("NamePanel setting session id.");
            CMS.setConfigSDSessionId(session_id);
        }

        mCerts = new Vector<Cert>();

        String domainname = "";
        IConfigStore config = CMS.getConfigStore();
        String select = "";
        String hselect = "";
        String cstype = "";
        String domainType = "";
        try {
            //if CA, at the hierarchy panel, was it root or subord?
            hselect = config.getString("preop.hierarchy.select", "");
            select = config.getString("preop.subsystem.select", "");
            cstype = config.getString("cs.type", "");
            domainType = config.getString("preop.securitydomain.select", "");
            context.put("select", select);
            if (cstype.equals("CA") && hselect.equals("root")) {
                CMS.debug("NamePanel ca is root");
                context.put("isRoot", "true");
            } else {
                CMS.debug("NamePanel not ca or not root");
                context.put("isRoot", "false");
            }
        } catch (Exception e) {
        }

        try {
            domainname = config.getString("securitydomain.name", "");

            String certTags = config.getString("preop.cert.list");
            // same token for now
            String token = config.getString(PRE_CONF_CA_TOKEN);
            StringTokenizer st = new StringTokenizer(certTags, ",");
            String domaintype = config.getString("securitydomain.select");
            int count = 0;
            String host = "";
            int sd_admin_port = -1;
            if (domaintype.equals("existing")) {
                host = config.getString("securitydomain.host", "");
                sd_admin_port = config.getInteger("securitydomain.httpsadminport", -1);
                count = ConfigurationUtils.getSubsystemCount(host, sd_admin_port, true, cstype);
            }

            while (st.hasMoreTokens()) {
                String certTag = st.nextToken();

                CMS.debug("NamePanel: display() about to process certTag :" + certTag);
                String nn = config.getString(
                        PCERT_PREFIX + certTag + ".nickname");
                Cert c = new Cert(token, nn, certTag);
                String userfriendlyname = config.getString(
                        PCERT_PREFIX + certTag + ".userfriendlyname");
                String subsystem = config.getString(
                        PCERT_PREFIX + certTag + ".subsystem");

                c.setUserFriendlyName(userfriendlyname);

                String type = config.getString(PCERT_PREFIX + certTag + ".type");
                c.setType(type);
                boolean enable = config.getBoolean(PCERT_PREFIX + certTag + ".enable", true);
                c.setEnable(enable);

                String cert = config.getString(subsystem + "." + certTag + ".cert", "");
                String certreq =
                        config.getString(subsystem + "." + certTag + ".certreq", "");

                String dn = config.getString(PCERT_PREFIX + certTag + ".dn");
                boolean override = config.getBoolean(PCERT_PREFIX + certTag +
                        ".cncomponent.override", true);
                //o_sd is to add o=secritydomainname
                boolean o_sd = config.getBoolean(PCERT_PREFIX + certTag +
                         "o_securitydomain", true);
                domainname = config.getString("securitydomain.name", "");
                CMS.debug("NamePanel: display() override is " + override);
                CMS.debug("NamePanel: display() o_securitydomain is " + o_sd);
                CMS.debug("NamePanel: display() domainname is " + domainname);

                boolean dnUpdated = false;
                try {
                    dnUpdated = config.getBoolean(PCERT_PREFIX + certTag + ".updatedDN");
                } catch (Exception e) {
                }

                try {
                    @SuppressWarnings("unused")
                    boolean done = config.getBoolean("preop.NamePanel.done"); // check for errors
                    c.setDN(dn);
                } catch (Exception e) {
                    String instanceId = config.getString("service.instanceID", "");
                    if (select.equals("clone") || dnUpdated) {
                        c.setDN(dn);
                    } else if (count != 0 && override && (cert.equals("") || certreq.equals(""))) {
                        CMS.debug("NamePanel subsystemCount = " + count);
                        c.setDN(dn + " " + count +
                                ((!instanceId.equals("")) ? (",OU=" + instanceId) : "") +
                                ((o_sd) ? (",O=" + domainname) : ""));
                        config.putBoolean(PCERT_PREFIX + certTag + ".updatedDN", true);
                    } else {
                        c.setDN(dn +
                                ((!instanceId.equals("")) ? (",OU=" + instanceId) : "") +
                                ((o_sd) ? (",O=" + domainname) : ""));
                        config.putBoolean(PCERT_PREFIX + certTag + ".updatedDN", true);
                    }
                }

                mCerts.addElement(c);
                CMS.debug(
                        "NamePanel: display() added cert to mCerts: certTag "
                                + certTag);
                config.putString(PCERT_PREFIX + c.getCertTag() + ".dn", c.getDN());
            }// while
        } catch (EBaseException e) {
            CMS.debug("NamePanel: display() exception caught:" + e.toString());
        } catch (Exception e) {
            CMS.debug("NamePanel: " + e.toString());
        }

        CMS.debug("NamePanel: Ready to get SSL EE HTTPS urls");
        Vector<String> v = null;
        if (!domainType.equals("new")) {
            try {
                v = ConfigurationUtils.getUrlListFromSecurityDomain(config, "CA", "SecurePort");
            } catch (Exception e) {
                CMS.debug("NamePanel: display(): Exception thrown in getUrlListFromSecurityDomain " + e);
                e.printStackTrace();
            }
        }
        if (v == null) {
            v = new Vector<String>();
        }
        v.addElement("External CA");

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
            config.putString("preop.ca.list", list.toString());
            config.commit(false);
        } catch (Exception e) {
        }

        context.put("urls", v);

        context.put("certs", mCerts);
        context.put("panel", "admin/console/config/namepanel.vm");
        context.put("errorString", "");

    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        Enumeration<Cert> c = mCerts.elements();

        while (c.hasMoreElements()) {
            Cert cert = c.nextElement();
            // get the dn's and put in config
            if (cert.isEnable()) {
                String dn = HttpInput.getDN(request, cert.getCertTag());

                if (dn == null || dn.length() == 0) {
                    context.put("updateStatus", "validate-failure");
                    throw new IOException("Empty DN for " + cert.getUserFriendlyName());
                }
            }
        } // while
    }

    public void configCertWithTag(HttpServletRequest request,
            HttpServletResponse response,
            Context context, String tag) throws IOException {
        CMS.debug("NamePanel: configCertWithTag start");
        Enumeration<Cert> c = mCerts.elements();
        IConfigStore config = CMS.getConfigStore();

        while (c.hasMoreElements()) {
            Cert cert = c.nextElement();
            String ct = cert.getCertTag();
            CMS.debug("NamePanel: configCertWithTag ct=" + ct + " tag=" + tag);
            if (ct.equals(tag)) {
                try {
                    String nickname = HttpInput.getNickname(request, ct + "_nick");
                    if (nickname != null) {
                        CMS.debug("configCertWithTag: Setting nickname for " + ct + " to " + nickname);
                        config.putString(PCERT_PREFIX + ct + ".nickname", nickname);
                        cert.setNickname(nickname);
                        config.commit(false);
                    }
                    String dn = HttpInput.getDN(request, ct);
                    if (dn != null) {
                        config.putString(PCERT_PREFIX + ct + ".dn", dn);
                        config.commit(false);
                    }
                } catch (Exception e) {
                    CMS.debug("NamePanel: configCertWithTag: Exception in setting nickname for "
                            + ct + ": " + e.toString());
                }

                ConfigurationUtils.configCert(request, response, context, cert, this);
                CMS.debug("NamePanel: configCertWithTag done with tag=" + tag);
                return;
            }
        }
        CMS.debug("NamePanel: configCertWithTag done");
    }

    private boolean inputChanged(HttpServletRequest request)
            throws IOException {
        IConfigStore config = CMS.getConfigStore();

        boolean hasChanged = false;
        try {
            Enumeration<Cert> c = mCerts.elements();

            while (c.hasMoreElements()) {
                Cert cert = c.nextElement();
                String ct = cert.getCertTag();
                boolean enable = config.getBoolean(PCERT_PREFIX + ct + ".enable", true);
                if (!enable)
                    continue;

                String olddn = config.getString(PCERT_PREFIX + cert.getCertTag() + ".dn", "");
                // get the dn's and put in config
                String dn = HttpInput.getDN(request, cert.getCertTag());

                if (!olddn.equals(dn))
                    hasChanged = true;

                String oldnick = config.getString(PCERT_PREFIX + ct + ".nickname");
                String nick = HttpInput.getNickname(request, ct + "_nick");
                if (!oldnick.equals(nick))
                    hasChanged = true;

            }
        } catch (Exception e) {
        }

        return hasChanged;
    }

    public String getURL(HttpServletRequest request, IConfigStore config) {
        String index = request.getParameter("urls");
        if (index == null) {
            return null;
        }
        String url = "";
        if (index.startsWith("http")) {
            // user may submit url directlry
            url = index;
        } else {
            try {
                int x = Integer.parseInt(index);
                String list = config.getString("preop.ca.list", "");
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
        }
        return url;
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        CMS.debug("NamePanel: in update()");

        if (inputChanged(request)) {
            mServlet.cleanUpFromPanel(mServlet.getPanelNo(request));
        } else if (isPanelDone()) {
            context.put("updateStatus", "success");
            return;
        }

        IConfigStore config = CMS.getConfigStore();
        ISubsystem subsystem = CMS.getSubsystem(ICertificateAuthority.ID);

        try {
            //if CA, at the hierarchy panel, was it root or subord?
            String hselect = config.getString("preop.hierarchy.select", "");
            String cstype = config.getString("preop.subsystem.select", "");
            if (cstype.equals("clone")) {
                CMS.debug("NamePanel: clone configuration detected");
                // still need to handle SSL certificate
                configCertWithTag(request, response, context, "sslserver");
                String url = getURL(request, config);
                if (url != null && !url.equals("External CA")) {
                    // preop.ca.url and admin port are required for setting KRA connector
                    url = url.substring(url.indexOf("https"));
                    config.putString("preop.ca.url", url);

                    URL urlx = new URL(url);
                    updateCloneSDCAInfo(request, context, urlx.getHost(), urlx.getPort());

                }
                ConfigurationUtils.updateCloneConfig();
                CMS.debug("NamePanel: clone configuration done");
                context.put("updateStatus", "success");
                return;
            }

            //if no hselect, then not CA
            if (hselect.equals("") || hselect.equals("join")) {
                String url = getURL(request, config);

                URL urlx = null;

                if (url.equals("External CA")) {
                    CMS.debug("NamePanel: external CA selected");
                    config.putString("preop.ca.type", "otherca");
                    if (subsystem != null) {
                        config.putString(PCERT_PREFIX + "signing.type", "remote");
                    }

                    config.putString("preop.ca.pkcs7", "");
                    config.putInteger("preop.ca.certchain.size", 0);
                    context.put("check_otherca", "checked");
                    CMS.debug("NamePanel: update: this is the external CA.");
                } else {
                    CMS.debug("NamePanel: local CA selected");
                    url = url.substring(url.indexOf("https"));
                    config.putString("preop.ca.url", url);

                    urlx = new URL(url);
                    String host = urlx.getHost();
                    int port = urlx.getPort();
                    String domainXML = config.getString("preop.domainXML");
                    int admin_port = ConfigurationUtils.getPortFromSecurityDomain(domainXML,
                            host, port, "CA", "SecurePort", "SecureAdminPort");

                    config.putString("preop.ca.type", "sdca");
                    config.putString("preop.ca.hostname", host);
                    config.putInteger("preop.ca.httpsport", port);
                    config.putInteger("preop.ca.httpsadminport", admin_port);

                    context.put("check_sdca", "checked");
                    context.put("sdcaHostname", host);
                    context.put("sdHttpPort", port);

                    ConfigurationUtils.importCertChain(host, admin_port, "/ca/admin/ca/getCertChain", "ca");

                    if (subsystem != null) {
                        config.putString(PCERT_PREFIX + "signing.type", "remote");
                        config.putString(PCERT_PREFIX + "signing.profile", "caInstallCACert");
                    }
                }
                config.commit(false);

            }

            Enumeration<Cert> c = mCerts.elements();

            while (c.hasMoreElements()) {
                Cert cert = c.nextElement();
                String ct = cert.getCertTag();
                boolean enable = config.getBoolean(PCERT_PREFIX + ct + ".enable", true);
                if (!enable)
                    continue;

                boolean certDone = config.getBoolean(PCERT_PREFIX + ct + ".done", false);
                if (certDone)
                    continue;

                // get the nicknames and put in config
                String nickname = HttpInput.getNickname(request, ct + "_nick");
                if (nickname != null) {
                    CMS.debug("NamePanel: update: Setting nickname for " + ct + " to " + nickname);
                    config.putString(PCERT_PREFIX + ct + ".nickname", nickname);
                    cert.setNickname(nickname);
                } else {
                    nickname = cert.getNickname();
                }

                // get the dn's and put in config
                String dn = HttpInput.getDN(request, ct);

                config.putString(PCERT_PREFIX + ct + ".dn", dn);
                // commit here in case it changes
                config.commit(false);

                ConfigurationUtils.configCert(request, response, context, cert, this);
                config.putBoolean("preop.cert." + cert.getCertTag() + ".done", true);
                config.commit(false);

            } // while

            config.putBoolean("preop.NamePanel.done", true);
            config.commit(false);
        } catch (Exception e) {
            CMS.debug("NamPanel - update(): Exception thrown : " + e);
            e.printStackTrace();
            context.put("updateStatus", "failure");
            throw new IOException(e);
        }
        context.put("updateStatus", "success");

        CMS.debug("NamePanel: update() done");
    }

    private void updateCloneSDCAInfo(HttpServletRequest request, Context context, String hostname, int httpsPort)
            throws IOException, EPropertyNotFound, EBaseException, SAXException, ParserConfigurationException {
        CMS.debug("NamePanel updateCloneSDCAInfo: selected CA hostname=" + hostname + " port=" + httpsPort);
        IConfigStore config = CMS.getConfigStore();

        if (hostname == null || hostname.length() == 0) {
            context.put("errorString", "Hostname is null");
            throw new IOException("Hostname is null");
        }

        // Retrieve the associated HTTPS Admin port so that it
        // may be stored for use with ImportAdminCertPanel
        String domainXML = config.getString("preop.domainXML");
        int https_admin_port = ConfigurationUtils.getPortFromSecurityDomain(domainXML,
                hostname, httpsPort, "CA", "SecurePort", "SecureAdminPort");

        config.putString("preop.ca.hostname", hostname);
        config.putInteger("preop.ca.httpsport", httpsPort);
        config.putInteger("preop.ca.httpsadminport", https_admin_port);
    }

    public void initParams(HttpServletRequest request, Context context)
                   throws IOException {
        context.put("certs", mCerts);
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        try {
            initParams(request, context);
        } catch (IOException e) {
        }
        context.put("title", "Subject Names");
        context.put("panel", "admin/console/config/namepanel.vm");
    }
}
