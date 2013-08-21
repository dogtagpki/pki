package com.netscape.cms.servlet.csadmin;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.lang.StringUtils;
import org.apache.velocity.context.Context;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.crypto.TokenException;
import org.xml.sax.SAXException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.certsrv.util.HttpInput;
import com.netscape.cms.servlet.wizard.WizardServlet;

public class CAInfoPanel extends WizardPanelBase {

    public CAInfoPanel() {
    }

    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("CA Information");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("CA Information");
        setId(id);
    }

    public boolean shouldSkip() {
        return false;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putString("preop.cainfo.select", "");
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.cainfo.select", "");
            if (s != null && !s.isEmpty()) {
                return true;
            }
        } catch (EBaseException e) {
        }
        return false;
    }

    public PropertySet getUsage() {
        return new PropertySet();
    }

    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        String errorString = "";
        context.put("title", "CA Information");
        context.put("panel", "admin/console/config/cainfopanel.vm");
        IConfigStore config = CMS.getConfigStore();

        if (isPanelDone()) {
            // TODO - put the selected URL in selection box.
            // String s = config.getString("preop.cainfo.select");
        }

        // get CA URLs
        Vector<String> v;
        try {
            v = null;
            v = ConfigurationUtils.getUrlListFromSecurityDomain(config, "CA", "SecurePort");
            if (v == null) {
                errorString = "No CA found.  CA, TKS and optionally DRM " +
                              " must be installed prior to TPS installation";
                context.put("errorString", errorString);
                context.put("preop.cainfo.errorString", errorString);
                return;
            }

            config.putString("preop.ca.list", StringUtils.join(v,","));
            config.commit(false);
        } catch (EBaseException | IOException | SAXException | ParserConfigurationException e) {
            e.printStackTrace();
            errorString = "Failed to get CA information from security domain. " + e;
            context.put("errorString", errorString);
            context.put("preop.cainfo.errorString", errorString);
            return;
        }

        context.put("urls", v);
        context.put("urls_size", v.size());
        context.put("errorString", "");
        context.put("preop.cainfo.errorString", "");
    }

    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
    }

    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        IConfigStore config = CMS.getConfigStore();
        String subsystemNick;
        try {
            subsystemNick = config.getString("preop.cert.subsystem.nickname");
        } catch (EBaseException e1) {
            e1.printStackTrace();
            throw new IOException("Failed to get subsystem certificate nickname");
        }

        String url = HttpInput.getString(request, "urls");
        URI caUri = null;
        String parsedURI = url.substring(url.lastIndexOf("http"));
        try {
            caUri = new URI(parsedURI);
        } catch (URISyntaxException e) {
            throw new IOException("Invalid URI " + parsedURI);
        }
        ConfigurationUtils.updateCAConnInfo(caUri, subsystemNick);

        String host = caUri.getHost();
        int port = caUri.getPort();

        // Note -
        // list contains EE port. If admin port is different, it needs to
        // be obtained from security domain and used to get the cert chain

        /* int admin_port = ConfigurationUtils.getPortFromSecurityDomain(domainXML,
                host, port, "CA", "SecurePort", "SecureAdminPort");
        */

        try {
            ConfigurationUtils.importCertChain(host, port, "/ca/admin/ca/getCertChain", "ca");
        } catch (CertificateException | SAXException | ParserConfigurationException
                | NotInitializedException | TokenException | EBaseException e) {
            e.printStackTrace();
            throw new IOException("Failed to import certificate chain from CA");
        }

        context.put("updateStatus", "success");
    }

    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
    }
}
