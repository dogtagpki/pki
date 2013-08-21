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

public class DRMInfoPanel extends WizardPanelBase {

    public DRMInfoPanel() {
    }

    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("DRM Information");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("DRM Information");
        setId(id);
    }

    public boolean shouldSkip() {
        return false;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putString("preop.krainfo.select", "");
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.krainfo.select", "");
            if (s != null && ! s.isEmpty()) {
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
        context.put("title", "DRM Information");
        context.put("panel", "admin/console/config/drminfopanel.vm");
        IConfigStore config = CMS.getConfigStore();

        if (isPanelDone()) {
            //TODO - put selected entry in selection box.
            //String s = config.getString("preop.krainfo.select");
        }

        // get KRA URLs
        Vector<String> v = null;
        try {
            v = ConfigurationUtils.getUrlListFromSecurityDomain(config, "KRA", "SecurePort");
            if (v == null) {
                errorString = "No DRM found.  CA, TKS and optionally DRM " +
                              " must be installed prior to TPS installation";
                context.put("errorString", errorString);
                context.put("preop.krainfo.errorString", errorString);
                return;
            }

            config.putString("preop.kra.list", StringUtils.join(v,","));
            config.commit(false);
        } catch (EBaseException | IOException | SAXException | ParserConfigurationException e1) {
            e1.printStackTrace();
            errorString = "Failed to get DRM information from security domain. " + e1;
            context.put("errorString", errorString);
            context.put("preop.krainfo.errorString", errorString);
            return;
        }

        context.put("urls", v);
        context.put("urls_size", v.size());
        context.put("errorString", "");
        context.put("preop.krainfo.errorString", "");
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
        URI kraUri = null;
        try {
            kraUri = new URI(parsedURI);
        } catch (URISyntaxException e) {
            throw new IOException("Invalid URI " + parsedURI);
        }

        String choice = HttpInput.getString(request, "choice");
        boolean keyGen = choice.equalsIgnoreCase("keygen");

        ConfigurationUtils.updateKRAConnInfo(keyGen, kraUri, subsystemNick);

        context.put("updateStatus", "success");
    }

    /**
     * If validate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
    }
}
