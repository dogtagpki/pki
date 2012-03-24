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
        String default_admin_url = "";
        String name = "";
        String cstype = "";
        String systemdService = "";

        try {
            default_admin_url = config.getString("preop.securitydomain.admin_url", "");
            name = config.getString("preop.securitydomain.name", "");
            cstype = config.getString("cs.type", "");
            systemdService = config.getString("pkicreate.systemd.servicename", "");
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
            context.put("http_ee_port", CMS.getEENonSSLPort());
            context.put("https_agent_port", CMS.getAgentPort());
            context.put("https_ee_port", CMS.getEESSLPort());
            context.put("https_admin_port", CMS.getAdminPort());
            context.put("sdomainAdminURL", default_admin_url);
        } catch (EBaseException e) {}

        context.put("panel", "admin/console/config/securitydomainpanel.vm");
        context.put("errorString", errorString);

        // from default_admin_url, find hostname, if fully qualified, get
        // network domain name and generate default security domain name
        if (name.equals("") && (default_admin_url != null)) {
            try {
                URL u = new URL(default_admin_url);

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

        if( default_admin_url != null ) {
            String r = null;

            try {
                // check to see if "default" security domain exists
                // on local machine
                URL u = new URL( default_admin_url );

                String hostname = u.getHost();
                int port = u.getPort();
                ConfigCertApprovalCallback
                certApprovalCallback = new ConfigCertApprovalCallback();
                r = pingCS( hostname, port, true, certApprovalCallback );
            } catch (Exception e) {
                CMS.debug( "SecurityDomainPanel: exception caught: "
                         + e.toString() );
            }
 
            if( r != null ) {
                // "default" security domain exists on local machine;
                // fill "sdomainURL" in with "default" security domain
                // as an initial "guess"
                CMS.debug( "SecurityDomainPanel: pingCS returns: "+r );
                context.put( "sdomainURL", default_admin_url );
            } else {
                // "default" security domain does NOT exist on local machine;
                // leave "sdomainURL" blank
                CMS.debug( "SecurityDomainPanel: pingCS no successful response" );
                context.put( "sdomainURL", "" );
            }
        }

        // Information for "existing" Security Domain CAs
        String initDaemon = "pki-cad";
        String instanceId = "&lt;security_domain_instance_name&gt;";
        String os = System.getProperty( "os.name" );
        if( os.equalsIgnoreCase( "Linux" ) ) {
            if (! systemdService.equals("")) {
                context.put( "initCommand", "/usr/bin/pkicontrol" );
                context.put( "instanceId", "ca " + systemdService );
            } else {
                context.put( "initCommand", "/sbin/service " + initDaemon );
                context.put( "instanceId", instanceId );
            }
        } else {
            /* default case:  e. g. - ( os.equalsIgnoreCase( "SunOS" ) */
            context.put( "initCommand", "/etc/init.d/" + initDaemon );
            context.put( "instanceId", instanceId );
        }
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
                context.put("updateStatus", "validate-failure");
                throw new IOException("Missing name value for the security domain");
            }
        } else if (select.equals("existingdomain")) {
            CMS.debug( "SecurityDomainPanel: validating "
                     + "SSL Admin HTTPS . . ." );
            String admin_url = HttpInput.getURL( request, "sdomainURL" );
            if( admin_url == null || admin_url.equals("") ) {
                initParams( request, context );
                context.put("updateStatus", "validate-failure");
                throw new IOException( "Missing SSL Admin HTTPS url value "
                                     + "for the security domain" );
            } else {
                String r = null;

                try {
                    URL u = new URL( admin_url );

                    String hostname = u.getHost();
                    int admin_port = u.getPort();
                    ConfigCertApprovalCallback
                    certApprovalCallback = new ConfigCertApprovalCallback();
                    r = pingCS( hostname, admin_port, true,
                                certApprovalCallback );
                } catch( Exception e ) {
                    CMS.debug( "SecurityDomainPanel: exception caught: "
                             + e.toString() );
                    context.put("updateStatus", "validate-failure");
                    throw new IOException( "Illegal SSL Admin HTTPS url value "
                                         + "for the security domain" );
                }

                if (r != null) {
                    CMS.debug("SecurityDomainPanel: pingAdminCS returns: "
                             + r );
                    context.put( "sdomainURL", admin_url );
                } else {
                    CMS.debug( "SecurityDomainPanel: pingAdminCS "
                             + "no successful response for SSL Admin HTTPS" );
                    context.put( "sdomainURL", "" );
                }
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

        String admin_url = request.getParameter("sdomainURL");
        if (admin_url == null)
            admin_url = "";
        context.put("sdomainURL", admin_url);
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
            context.put("updateStatus", "failure");
            throw new IOException("choice not found");
        }
        IConfigStore config = CMS.getConfigStore();

        if (select.equals("newdomain")) {
            config.putString("preop.securitydomain.select", "new");
            config.putString("securitydomain.select", "new");
            config.putString("preop.securitydomain.name", 
              HttpInput.getDomainName(request, "sdomainName"));
            config.putString("securitydomain.name", 
              HttpInput.getDomainName(request, "sdomainName"));
            config.putString("securitydomain.host", 
              CMS.getEENonSSLHost());
            config.putString("securitydomain.httpport", 
              CMS.getEENonSSLPort());
            config.putString("securitydomain.httpsagentport", 
              CMS.getAgentPort());
            config.putString("securitydomain.httpseeport", 
              CMS.getEESSLPort());
            config.putString("securitydomain.httpsadminport", 
              CMS.getAdminPort());

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

            String admin_url = HttpInput.getURL(request, "sdomainURL");
            String hostname = "";
            int admin_port = -1;

            if( admin_url != null ) {
                try {
                    URL admin_u = new URL( admin_url );

                    hostname = admin_u.getHost();
                    admin_port = admin_u.getPort();
                } catch( MalformedURLException e ) {
                    errorString = "Malformed SSL Admin HTTPS URL";
                    context.put("updateStatus", "failure");
                    throw new IOException( errorString );
                }

                context.put( "sdomainURL", admin_url );
                config.putString( "securitydomain.host", hostname );
                config.putInteger( "securitydomain.httpsadminport",
                                   admin_port );
            }

            try {
                config.commit(false);
            } catch (EBaseException e) {}

            ConfigCertApprovalCallback certApprovalCallback = new ConfigCertApprovalCallback();
            updateCertChain( config, "securitydomain", hostname, admin_port,
                             true, context, certApprovalCallback );
        } else {
            CMS.debug("SecurityDomainPanel: invalid choice " + select);
            errorString = "Invalid choice";
            context.put("updateStatus", "failure");
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
        context.put("updateStatus", "success");
    }

    /**
     * If validate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        IConfigStore config = CMS.getConfigStore();
        String default_admin_url = "";
        try {
            initParams(request, context);
        } catch (IOException e) {
        }

        try {
            default_admin_url = config.getString("preop.securitydomain.admin_url", "");
        } catch (Exception e) {}

        if( default_admin_url != null ) {
            String r = null;

            try {
                // check to see if "default" security domain exists
                // on local machine
                URL u = new URL( default_admin_url );

                String hostname = u.getHost();
                int port = u.getPort();
                ConfigCertApprovalCallback
                certApprovalCallback = new ConfigCertApprovalCallback();
                r = pingCS( hostname, port, true, certApprovalCallback );
            } catch (Exception e) {}
 
            if( r != null ) {
                // "default" security domain exists on local machine;
                // refill "sdomainURL" in with "default" security domain
                // as an initial "guess"
                context.put( "sdomainURL", default_admin_url );
            } else {
                // "default" security domain does NOT exist on local machine;
                // leave "sdomainURL" blank
                context.put( "sdomainURL", "" );
            }
        }

        try {
            context.put("machineName", config.getString("machineName"));
            context.put("http_ee_port", CMS.getEENonSSLPort());
            context.put("https_agent_port", CMS.getAgentPort());
            context.put("https_ee_port", CMS.getEESSLPort());
            context.put("https_admin_port", CMS.getAdminPort());
            context.put("sdomainAdminURL",
                        config.getString("preop.securitydomain.admin_url"));
        } catch (EBaseException e) {}

        // Information for "existing" Security Domain CAs
        String initDaemon = "pki-cad";
        String instanceId = "&lt;security_domain_instance_name&gt;";
        String os = System.getProperty( "os.name" );
        if( os.equalsIgnoreCase( "Linux" ) ) {
            context.put( "initCommand", "/sbin/service " + initDaemon );
            context.put( "instanceId", instanceId );
        } else {
            /* default case:  e. g. - ( os.equalsIgnoreCase( "SunOS" ) */
            context.put( "initCommand", "/etc/init.d/" + initDaemon );
            context.put( "instanceId", instanceId );
        }

        context.put("title", "Security Domain");
        context.put("panel", "admin/console/config/securitydomainpanel.vm");
    }
}
