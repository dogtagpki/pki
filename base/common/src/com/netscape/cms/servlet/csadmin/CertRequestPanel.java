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
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.util.CertPrettyPrint;

import org.apache.velocity.context.Context;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.property.Descriptor;
import com.netscape.certsrv.property.IDescriptor;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.certsrv.util.HttpInput;
import com.netscape.cms.servlet.wizard.WizardServlet;
import com.netscape.cmsutil.crypto.CryptoUtil;

public class CertRequestPanel extends WizardPanelBase {
    private Vector<Cert> mCerts = null;

    @SuppressWarnings("unused")
    private WizardServlet mServlet;

    public CertRequestPanel() {
    }

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Requests & Certificates");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("Requests and Certificates");
        mServlet = servlet;
        setId(id);
    }

    // XXX how do you do this?  There could be multiple certs.
    public PropertySet getUsage() {
        PropertySet set = new PropertySet();

        Descriptor certDesc = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameters */
                null);

        set.add("cert", certDesc);

        return set;
    }

    /**
     * Show "Apply" button on frame?
     */
    public boolean showApplyButton() {
        if (isPanelDone())
            return false;
        else
            return true;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        String list = "";
        String tokenname = "";
        try {
            list = cs.getString("preop.cert.list", "");
            tokenname = cs.getString("preop.module.token", "");
        } catch (Exception e) {
        }

        ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(
                ICertificateAuthority.ID);

        if (ca != null) {
            CMS.debug("CertRequestPanel cleanup: get certificate repository");
            BigInteger beginS = null;
            BigInteger endS = null;
            String beginNum = "";
            String endNum = "";
            try {
                beginNum = cs.getString("dbs.beginSerialNumber", "");
                endNum = cs.getString("dbs.endSerialNumber", "");
                if (!beginNum.equals(""))
                    beginS = new BigInteger(beginNum, 16);
                if (!endNum.equals(""))
                    endS = new BigInteger(endNum, 16);
            } catch (Exception e) {
            }

            ICertificateRepository cr = ca.getCertificateRepository();
            if (cr != null) {
                try {
                    cr.removeCertRecords(beginS, endS);
                } catch (Exception e) {
                    CMS.debug("CertRequestPanel cleanUp exception in removing all objects: " + e.toString());
                }

                try {
                    cr.resetSerialNumber(new BigInteger(beginNum, 16));
                } catch (Exception e) {
                    CMS.debug("CertRequestPanel cleanUp exception in resetting serial number: " + e.toString());
                }
            }
        }

        StringTokenizer st = new StringTokenizer(list, ",");
        String nickname = "";
        boolean enable = false;
        while (st.hasMoreTokens()) {
            String t = st.nextToken();

            try {
                enable = cs.getBoolean(PCERT_PREFIX + t + ".enable", true);
                nickname = cs.getString(PCERT_PREFIX + t + ".nickname", "");
            } catch (Exception e) {
            }

            if (!enable)
                continue;

            if (t.equals("sslserver"))
                continue;

            try {
                if (ConfigurationUtils.findCertificate(tokenname, nickname)) {
                    CMS.debug("CertRequestPanel cleanup: deleting certificate (" + nickname + ").");
                    ConfigurationUtils.deleteCert(tokenname, nickname);
                }
            } catch (Exception e) {
                CMS.debug("CertRequestPanel cleanup: failed to delete certificate ("
                        + nickname + "). Exception: " + e.toString());
            }
        }

        try {
            @SuppressWarnings("unused")
            boolean done = cs.getBoolean("preop.CertRequestPanel.done"); // check for errors
            cs.putBoolean("preop.CertRequestPanel.done", false);
            cs.commit(false);
        } catch (Exception e) {
        }
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            boolean s = cs.getBoolean("preop.CertRequestPanel.done",
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

    public void getCert(IConfigStore config,
            Context context, String certTag, Cert cert) {
        try {

            String subsystem = config.getString(PCERT_PREFIX + certTag + ".subsystem");
            String certs = config.getString(subsystem + "." + certTag + ".cert", "");

            if (cert != null) {
                String certf = certs;

                CMS.debug("CertRequestPanel getCert: certTag=" + certTag + " cert=" + certs);

                //get and set formated cert
                if (!certs.startsWith("...")) {
                    certf = CryptoUtil.certFormat(certs);
                }
                cert.setCert(certf);

                //get and set cert pretty print
                byte[] certb = CryptoUtil.base64Decode(certs);
                CertPrettyPrint pp = new CertPrettyPrint(certb);
                cert.setCertpp(pp.toString(Locale.getDefault()));
            } else {
                CMS.debug("CertRequestPanel::getCert() - cert is null!");
                return;
            }
            String userfriendlyname = config.getString(
                    PCERT_PREFIX + certTag + ".userfriendlyname");

            cert.setUserFriendlyName(userfriendlyname);
            String type = config.getString(PCERT_PREFIX + certTag + ".type");

            cert.setType(type);
            String dn = config.getString(PCERT_PREFIX + certTag + ".dn");

            cert.setDN(dn);
        } catch (Exception e) {
            CMS.debug("CertRequestPanel:getCert" + e.toString());
        } // try
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        CMS.debug("CertRequestPanel: display()");
        context.put("title", "Requests and Certificates");

        try {
            mCerts = new Vector<Cert>();

            IConfigStore config = CMS.getConfigStore();

            String certTags = config.getString("preop.cert.list");
            String csType = config.getString("cs.type");
            StringTokenizer st = new StringTokenizer(certTags, ",");

            while (st.hasMoreTokens()) {
                String certTag = st.nextToken();

                try {
                    String subsystem = config.getString(PCERT_PREFIX + certTag + ".subsystem");
                    String nickname = config.getString(subsystem + "." + certTag + ".nickname");
                    String tokenname = config.getString(subsystem + "." + certTag + ".tokenname");

                    Cert c = new Cert(tokenname, nickname, certTag);
                    ConfigurationUtils.handleCertRequest(config, certTag, c);

                    String type = config.getString(PCERT_PREFIX + certTag + ".type");
                    c.setType(type);

                    boolean enable = config.getBoolean(PCERT_PREFIX + certTag + ".enable", true);
                    c.setEnable(enable);
                    getCert(config, context, certTag, c);

                    c.setSubsystem(subsystem);
                    mCerts.addElement(c);

                    if (csType.equals("TPS") && certTag.equals("subsystem")) {
                        // update nicknames in case they have changed
                        if (!tokenname.isEmpty() && !tokenname.equals("internal")
                                && !tokenname.equals("Internal Key Storage Token"))
                            nickname = tokenname + ":" + nickname;

                        config.putString("conn.ca1.clientNickname", nickname);
                        config.putString("conn.drm1.clientNickname", nickname);
                        config.putString("conn.tks1.clientNickname", nickname);
                    }
                } catch (Exception e) {
                    CMS.debug("CertRequestPanel:display() Exception caught: " + e.toString() +
                            " for certTag " + certTag);
                }
            }
        } catch (Exception e) {
            CMS.debug("CertRequestPanel:display() Exception caught: " + e.toString());
            System.err.println("Exception caught: " + e.toString());

        } // try

        context.put("reqscerts", mCerts);
        context.put("status", "display");
        // context.put("status_token", "None");
        context.put("panel", "admin/console/config/certrequestpanel.vm");

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
        CMS.debug("CertRequestPanel: in update()");
        boolean hasErr = false;
        IConfigStore config = CMS.getConfigStore();

        if (isPanelDone()) {
            context.put("updateStatus", "success");
            return;
        }

        Enumeration<Cert> c = mCerts.elements();
        while (c.hasMoreElements()) {
            Cert cert = c.nextElement();
            if (hasErr) continue;

            int ret=0;
            try {
                cert.setCert(HttpInput.getCert(request, cert.getCertTag()));
                cert.setCertChain(HttpInput.getCertChain(request, cert.getCertTag() + "_cc"));

                ret = ConfigurationUtils.handleCerts(cert);
                ConfigurationUtils.setCertPermissions(cert.getCertTag());
            } catch (Exception e) {
                CMS.debug("Exception in configuring system certificate " + cert.getCertTag() + ": " + e);
                e.printStackTrace();
                hasErr = true;
            }
            if (ret != 0) {
                CMS.debug("System certificates not configured " +  cert.getCertTag());
            }
        }
        // end new

        if (!hasErr) {
            try {
                config.putBoolean("preop.CertRequestPanel.done", true);
                config.commit(false);
            } catch (EBaseException e) {
                e.printStackTrace();
                CMS.debug("Unable to commit changes to CS,cfg: " +e);
            }
            context.put("updateStatus", "success");
        } else {
            context.put("updateStatus", "failure");
        }
    }

    /**
     * If validate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("title", "Certificate Request");
        context.put("panel", "admin/console/config/certrequestpanel.vm");
    }
}
