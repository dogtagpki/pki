package com.netscape.cms.servlet.csadmin;

import java.io.IOException;

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

public class AuthDBPanel extends WizardPanelBase {

    public AuthDBPanel() {
    }

    public void init(ServletConfig config, int panelno)
            throws ServletException {
        setPanelNo(panelno);
        setName("Authentication Directory");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
            throws ServletException {
        setPanelNo(panelno);
        setName("Authentication Directory");
        setId(id);
    }

    public boolean shouldSkip() {
        return false;
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putString("preop.authdb.select", "");
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.authdb.select", "");
            if (s != null && !s.isEmpty()) {
                return true;
            }
        } catch (EBaseException e) {
        }
        return false;
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();
        return set;
    }

    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        context.put("title", "Authentication Directory");
        context.put("panel", "admin/console/config/authdbpanel.vm");
        IConfigStore config = CMS.getConfigStore();

        String basedn="";
        String host="";
        String port="";
        String secureConn="";
        try {
            String machineName = config.getString("service.machineName");
            basedn = config.getString("auths.instance.ldap1.ldap.basedn");

            if (basedn.contains("[")) {
                // basedn not yet set
                basedn = machineName.replaceAll("\\.", ",dc=");
                basedn = "dc=" + basedn;
            }

            host = config.getString("auths.instance.ldap1.ldap.ldapconn.host", "localhost");
            port = config.getString("auths.instance.ldap1.ldap.ldapconn.port","389");
            secureConn = config.getString("auths.instance.ldap1.ldap.ldapconn.secureConn", "false");
        } catch (EBaseException e) {
            e.printStackTrace();
            CMS.debug("Unable to get host, port, secureConn:" + e);
        }

        context.put("hostname", host);
        context.put("portStr", port);
        context.put("basedn", basedn);
        context.put("secureconn", secureConn);
        context.put("errorString", "");
    }

    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
    }

    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {

        String host = HttpInput.getHostname(request, "host");
        String port = HttpInput.getPortNumber(request, "port");
        String basedn = HttpInput.getString(request,"basedn");
        String secureConn = HttpInput.getString(request, "secureConn");

        if (secureConn == null || (!secureConn.equalsIgnoreCase("true"))) {
            secureConn = "false";
        }
        ConfigurationUtils.updateAuthdbInfo(basedn, host, port, secureConn);
        context.put("updateStatus", "success");
    }

    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
    }

}
