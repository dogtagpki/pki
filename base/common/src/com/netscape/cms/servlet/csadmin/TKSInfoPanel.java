package com.netscape.cms.servlet.csadmin;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.lang.StringUtils;
import org.apache.velocity.context.Context;
import org.xml.sax.SAXException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.property.PropertySet;
import com.netscape.certsrv.util.HttpInput;
import com.netscape.cms.servlet.wizard.WizardServlet;

public class TKSInfoPanel extends WizardPanelBase {

    public TKSInfoPanel() {
    }

    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("TKS Information");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("TKS Information");
        setId(id);
    }

    public boolean shouldSkip() {
        return false;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putString("preop.tksinfo.select", "");
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.tksinfo.select", "");
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
        context.put("title", "TKS Information");
        context.put("panel", "admin/console/config/tksinfopanel.vm");
        IConfigStore config = CMS.getConfigStore();

        if (isPanelDone()) {
            // TODO - put selected URL in selection box
            // String s = config.getString("preop.tksinfo.select");
        }

        // get TKS URLs
        Vector<String> v = null;
        try {
            v = ConfigurationUtils.getUrlListFromSecurityDomain(config, "TKS", "SecureAdminPort");
            if (v == null) {
                errorString = "No TKS found.  CA, TKS and optionally DRM " +
                              " must be installed prior to TPS installation";
                context.put("errorString", errorString);
                context.put("preop.tksinfo.errorString", errorString);
                return;
            }

            config.putString("preop.tks.list", StringUtils.join(v,","));
            config.commit(false);
        } catch (EBaseException | IOException | SAXException | ParserConfigurationException e) {
            e.printStackTrace();
            errorString = "Failed to get TKS information from security domain. " + e;
            context.put("errorString", errorString);
            context.put("preop.tksinfo.errorString", errorString);
            return;
        }

        context.put("urls", v);
        context.put("urls_size", v.size());
        context.put("errorString", "");
        context.put("preop.tksinfo.errorString", "");
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
        String parsedURI = url.substring(url.lastIndexOf("http"));
        URI tksUri = null;
        try {
            tksUri = new URI(parsedURI);
        } catch (URISyntaxException e) {
            throw new IOException("Invalid URI " + parsedURI);
        }

        ConfigurationUtils.updateTKSConnInfo(tksUri, subsystemNick);
        context.put("updateStatus", "success");
    }

    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
    }

}
