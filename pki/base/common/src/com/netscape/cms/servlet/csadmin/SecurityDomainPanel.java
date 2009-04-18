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


import org.apache.velocity.Template;
import org.apache.velocity.servlet.VelocityServlet;
import org.apache.velocity.app.Velocity;
import org.apache.velocity.context.Context;
import javax.servlet.*;
import javax.servlet.http.*;
import org.mozilla.jss.crypto.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.base.*;
import com.netscape.cmsutil.crypto.*;
import java.net.*;
import java.io.*;
import java.util.*;
import java.security.cert.*;
import com.netscape.cmsutil.xml.*;
import org.w3c.dom.*;

import com.netscape.cms.servlet.wizard.*;

public class SecurityDomainPanel extends WizardPanelBase {

    public SecurityDomainPanel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Security Domain");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
        throws ServletException {
        setPanelNo(panelno);
        setName("Security Domain");
        setId(id);
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putString("preop.securitydomain.select", "");
        cs.putString("securitydomain.select", "");
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.securitydomain.select", "");
            if (s == null || s.equals("")) {
                return false;
            } else {
                return true;
            }
        } catch (EBaseException e) {}
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
        context.put("title", "Security Domain");
        IConfigStore config = CMS.getConfigStore();
        String errorString = "";
        String url = "";
        String name = "";

        try {
            url = config.getString("preop.securitydomain.url", "");
            name = config.getString("preop.securitydomain.name", "");
        } catch (Exception e) {
            CMS.debug(e.toString());
        }
        if (isPanelDone()) {
            try {
                String s = config.getString("preop.securitydomain.select");

                if (s.equals("new")) {
                    context.put("check_newdomain", "checked");
                    context.put("check_existingdomain", "");
                } else if (s.equals("existing")) {
                    context.put("check_newdomain", "");
                    context.put("check_existingdomain", "checked");
                }
            } catch (Exception e) {
                CMS.debug(e.toString());
            }
        } else {
            context.put("check_newdomain", "checked");
            context.put("check_existingdomain", "");
        }

        try {
            context.put("cstype", config.getString("cs.type"));
            context.put("wizardname", config.getString("preop.wizard.name"));
            context.put("panelname", "Security Domain Configuration");
            context.put("systemname", config.getString("preop.system.name"));
            context.put("machineName", config.getString("machineName"));
            context.put("https_port", CMS.getEESSLPort());
            context.put("http_port", CMS.getEENonSSLPort());
        } catch (EBaseException e) {}

        context.put("panel", "admin/console/config/securitydomainpanel.vm");
        context.put("errorString", errorString);

	if (url != null) {
            String r = null;

            try {
                URL u = new URL(url);

                String hostname = u.getHost();
                int port = u.getPort();
                ConfigCertApprovalCallback certApprovalCallback = new ConfigCertApprovalCallback();
                r = pingCS(hostname, port, true, certApprovalCallback);
	    } catch (Exception e) {
		CMS.debug("SecurityDomainPanel: exception caught: "+e.toString());
	    }

	    if (r != null) {
		CMS.debug("SecurityDomainPanel: pingCS returns: "+r);
		context.put("sdomainURL", url);
	    } else {
		CMS.debug("SecurityDomainPanel: pingCS no successful response");
		context.put("sdomainURL", "");
	    }
	}

        // from url, find hostname, if fully qualified, get network
        // domain name and generate default security domain name
        if (name.equals("") && (url != null)) {
            try {
                URL u = new URL(url);

                String hostname = u.getHost();
                StringTokenizer st = new StringTokenizer(hostname, ".");
		boolean first = true;
		int numTokens = st.countTokens();
		int count = 0;
        String defaultDomain = "";
        StringBuffer sb = new StringBuffer();
        while (st.hasMoreTokens()) {
		    count++;
		    String n = st.nextToken();
		    if (first) { //skip the hostname
			first = false;
			continue;
                    }
		    if (count == numTokens) // skip the last element (e.g. com)
			continue;
            sb.append((defaultDomain.length()==0)? "":" ");
            sb.append(capitalize(n));
		}
		defaultDomain = sb.toString() + " "+ "Domain";
		name = defaultDomain;
		CMS.debug("SecurityDomainPanel: defaultDomain generated:"+ name);
            } catch (MalformedURLException e) {
                errorString = "Malformed URL";
		// not being able to come up with default domain name is ok
            }
        }
        context.put("sdomainName", name);
    }

    public static String capitalize(String s) {
        if (s.length() == 0) {
            return s;
        } else {
            return s.substring(0,1).toUpperCase() + s.substring(1);
        }
    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
       
        String select = HttpInput.getID(request, "choice");
        if (select.equals("newdomain")) {
            String name = HttpInput.getSecurityDomainName(request, "sdomainName");
            if (name == null || name.equals("")) {
                initParams(request, context);
                throw new IOException("Missing name value for the security domain");
            }
        } else if (select.equals("existingdomain")) {
            String url = HttpInput.getURL(request, "sdomainURL");
            if (url == null || url.equals("")) {
                initParams(request, context);
                throw new IOException("Missing url value for the security domain");
            }
        }
    }

    public void initParams(HttpServletRequest request, Context context) 
                   throws IOException 
    {
        IConfigStore config = CMS.getConfigStore();
        try {
            context.put("cstype", config.getString("cs.type"));
        } catch (Exception e) {
        }

        String select = request.getParameter("choice");
        if (select.equals("newdomain")) {
            context.put("check_newdomain", "checked");
            context.put("check_existingdomain", "");
        } else if (select.equals("existingdomain")) {
            context.put("check_newdomain", ""); 
            context.put("check_existingdomain", "checked");
        }

        String name = request.getParameter("sdomainName");
        if (name == null)
            name = "";
        context.put("sdomainName", name);

        String url = request.getParameter("sdomainURL");
        if (url == null)
            url = "";
        context.put("sdomainURL", url);
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        String errorString = "";
        String select = HttpInput.getID(request, "choice");

        if (select == null) {
            CMS.debug("SecurityDomainPanel: choice not found");
            throw new IOException("choice not found");
        }
        IConfigStore config = CMS.getConfigStore();

        if (select.equals("newdomain")) {
            config.putString("preop.securitydomain.select", "new");
            config.putString("securitydomain.select", "new");
            config.putString("preop.securitydomain.host", 
              CMS.getEENonSSLHost());
            config.putString("securitydomain.host", 
              CMS.getEENonSSLHost());
            config.putString("preop.securitydomain.httpport", 
              CMS.getEENonSSLPort());
            config.putString("securitydomain.httpport", 
              CMS.getEENonSSLPort());
            config.putString("preop.securitydomain.httpsport", 
              CMS.getEESSLPort());
            config.putString("securitydomain.httpsport", 
              CMS.getEESSLPort());
            config.putString("preop.securitydomain.name", 
              HttpInput.getDomainName(request, "sdomainName"));
            config.putString("securitydomain.name", 
              HttpInput.getDomainName(request, "sdomainName"));

            // make sure the subsystem certificate is issued by the security  
            // domain
            config.putString("preop.cert.subsystem.type", "local");
            config.putString("preop.cert.subsystem.profile", "subsystemCert.profile");
   
            try {
                config.commit(false);
            } catch (EBaseException e) {}

            String instanceRoot = "";
            try {
                instanceRoot = config.getString("instanceRoot", "");
            } catch (Exception e) {
            }

        } else if (select.equals("existingdomain")) {
            config.putString("preop.securitydomain.select", "existing");
            config.putString("securitydomain.select", "existing");

            // make sure the subsystem certificate is issued by the security
            // domain
            config.putString("preop.cert.subsystem.type", "remote");
            config.putString("preop.cert.subsystem.profile", "caInternalAuthSubsystemCert");

            String url = HttpInput.getURL(request, "sdomainURL");
            String hostname = "";
            int port = -1;

            if (url != null) {
                try {
                    URL u = new URL(url);

                    hostname = u.getHost();
                    port = u.getPort();
                } catch (MalformedURLException e) {
                    errorString = "Malformed URL";
                    throw new IOException(errorString);            
                }
                
                context.put("sdomainURL", url);
                config.putString("preop.securitydomain.url", url);
                config.putString("preop.securitydomain.host", hostname);
                config.putString("securitydomain.host", hostname);
                config.putInteger("preop.securitydomain.httpsport", port);
                config.putInteger("securitydomain.httpsport", port);
            } else {
                config.putString("preop.securitydomain.url", "");
            }

            try {
                config.commit(false);
            } catch (EBaseException e) {}

            ConfigCertApprovalCallback certApprovalCallback = new ConfigCertApprovalCallback();
            updateCertChain(config, "securitydomain", hostname, port, true, 
              context, certApprovalCallback);
        } else {
            CMS.debug("SecurityDomainPanel: invalid choice " + select);
            errorString = "Invalid choice";
            throw new IOException("invalid choice " + select);
        }

        try {
            config.commit(false);
        } catch (EBaseException e) {
        }

        try {
            context.put("cstype", config.getString("cs.type"));
            context.put("wizardname", config.getString("preop.wizard.name"));
            context.put("panelname", "Security Domain Configuration");
            context.put("systemname", config.getString("preop.system.name"));
        } catch (EBaseException e) {}

        context.put("errorString", errorString);
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        IConfigStore config = CMS.getConfigStore();
        try {
            initParams(request, context);
        } catch (IOException e) {
        }
        try {
            context.put("machineName", config.getString("machineName"));
            context.put("https_port", CMS.getEESSLPort());
            context.put("http_port", CMS.getEENonSSLPort());
        } catch (EBaseException e) {}
        context.put("title", "Security Domain");
        context.put("panel", "admin/console/config/securitydomainpanel.vm");
    }
}
