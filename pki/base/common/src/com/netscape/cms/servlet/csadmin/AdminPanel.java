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
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.util.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.cmsutil.crypto.*;
import com.netscape.cmsutil.http.*;
import com.netscape.certsrv.template.*;
import com.netscape.certsrv.profile.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.authentication.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.ca.*;
import java.io.*;
import java.util.*;
import java.security.*;
import java.security.cert.*;
import java.net.*;
import javax.servlet.*;
import javax.servlet.http.*;
import netscape.ldap.*;
import netscape.security.util.*;
import netscape.security.pkcs.*;
import netscape.security.x509.*;
import com.netscape.cmsutil.xml.*;
import org.xml.sax.*;
import org.mozilla.jss.asn1.*;
import org.mozilla.jss.pkix.*;
import org.mozilla.jss.pkix.primitive.*;
import org.mozilla.jss.pkix.crmf.*;

import com.netscape.cms.servlet.wizard.*;
import com.netscape.certsrv.request.*;
import com.netscape.certsrv.dbs.certdb.*;

public class AdminPanel extends WizardPanelBase {

    private static final String ADMIN_UID = "admin";
    private final static String CERT_TAG = "admin";

    public AdminPanel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Administrator");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id) {
        setPanelNo(panelno);
        setName("Administrator");
        setId(id);
    }

    public void cleanUp() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        cs.putString("preop.admin.email", "");
    }

    public boolean isPanelDone() {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String s = cs.getString("preop.admin.email", "");
            if (s == null || s.equals("")) {
                return false;
            } else {
                return true;
            }
        } catch (Exception e) {}

        return false;
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();
                                                                                
        Descriptor emailDesc = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */
                "Email address for an administrator");

        set.add("admin_email", emailDesc);

        Descriptor pwdDesc = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */
                "Administrator's password");

        set.add("pwd", pwdDesc);

        Descriptor pwdAgainDesc = new Descriptor(IDescriptor.STRING, null, /* no constraint */
                null, /* no default parameter */
                "Administrator's password again");

        set.add("admin_password_again", pwdAgainDesc);
        return set;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        CMS.debug("AdminPanel: display");

        IConfigStore cs = CMS.getConfigStore();
        String session_id = request.getParameter("session_id");
        if (session_id != null) {
            CMS.debug("NamePanel setting session id.");
            CMS.setConfigSDSessionId(session_id);
        }

        String type = "";
        String info = "";
        context.put("import", "true");

        String subsystemtype = "";
        try {
            type = cs.getString("preop.ca.type", "");
            subsystemtype = cs.getString("cs.type", "");
        } catch (Exception e) {}

        if (isPanelDone()) {
            try {
                context.put("admin_email", cs.getString("preop.admin.email"));
                context.put("admin_name", cs.getString("preop.admin.name"));
                context.put("admin_pwd", "");
                context.put("admin_pwd_again", "");
                context.put("admin_uid", cs.getString("preop.admin.uid"));
            } catch (Exception e) {}
        } else {
            String def_admin_name = "";
            try {
              def_admin_name = cs.getString("cs.type") + " Administrator of Instance " + cs.getString("instanceId");
            } catch (EBaseException e) {
            }
            context.put("admin_name", def_admin_name);
            context.put("admin_email", "");
            context.put("admin_pwd", "");
            context.put("admin_pwd_again", "");
            context.put("admin_uid", ADMIN_UID);
        }
        ISubsystem ca = (ISubsystem) CMS.getSubsystem("ca");

        if (ca == null) { 
            context.put("ca", "false");
        } else {
            context.put("ca", "true");
        }
        context.put("caType", type);

        String domainname = "";
        try {
            domainname = cs.getString("securitydomain.name", "");
        } catch (EBaseException e1) {}
        context.put("securityDomain", domainname);
        context.put("title", "Administrator");
        context.put("panel", "admin/console/config/adminpanel.vm");
        context.put("errorString", "");
        context.put("info", info);
        
    }

    /**
     * Checks if the given parameters are valid.
     */
    public void validate(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException
    {
        String pwd = HttpInput.getPassword(request, "__pwd");
        String pwd_again = HttpInput.getPassword(request, "__admin_password_again");
        String email = HttpInput.getEmail(request, "email");
        String name = HttpInput.getName(request, "name");
        String uid = HttpInput.getUID(request, "uid");
        context.put("admin_email", email);
        context.put("admin_name", name);
        context.put("admin_pwd", pwd);
        context.put("admin_pwd_again", pwd_again);
        context.put("import", "true");

        if (name == null || name.equals(""))
            throw new IOException("Name is empty");

        if (email == null || email.equals(""))
            throw new IOException("Email is empty");

        if (uid == null || uid.equals(""))
            throw new IOException("Uid is empty");

        if (!pwd.equals(pwd_again)) {
            throw new IOException("Password and password again are not the same.");
        }

        if (email == null || email.length() == 0) {
            throw new IOException("Email address is empty string.");
        }
    }

    /**
     * Commit parameter changes
     */
    public void update(HttpServletRequest request,
            HttpServletResponse response,
            Context context) throws IOException {
        IConfigStore config = CMS.getConfigStore();
        context.put("info", "");
        context.put("import", "true");

        String type = "";
        String subsystemtype = "";
        String security_domain_type = "";
        String selected_hierarchy = "";
        try {
            type = config.getString(PRE_CA_TYPE, "");
            subsystemtype = config.getString("cs.type", "");
            security_domain_type = config.getString("securitydomain.select","");
            selected_hierarchy = config.getString("preop.hierarchy.select", "");
        } catch (Exception e) {}

        ISubsystem ca = (ISubsystem) CMS.getSubsystem("ca");

        if (ca == null) { 
            context.put("ca", "false");
        } else {
            context.put("ca", "true");
        }
        context.put("caType", type);
        String uid = HttpInput.getUID(request, "uid");
        String email = HttpInput.getEmail(request, "email");
        String name = HttpInput.getName(request, "name");

        CMS.debug("AdminPanel update: email address = " + email);
        String pwd = HttpInput.getPassword(request, "__pwd");

        config.putString("preop.admin.uid", uid);
        config.putString("preop.admin.email", email);
        config.putString("preop.admin.name", name);
        try {
            createAdmin(request);
        } catch (IOException e) {
            context.put("errorString", "Failed to create administrator.");
            throw e;
        }

        // REMINDER:  This panel is NOT used by "clones"
        if( ( ca != null ) && ( security_domain_type.equals( "new" ) ) ) {
            if( selected_hierarchy.equals( "root" ) ) {
                CMS.debug( "AdminPanel update:  "
                         + "Root CA subsystem - "
                         + "(new Security Domain)" );
            } else {
                CMS.debug( "AdminPanel update:  "
                         + "Subordinate CA subsystem - "
                         + "(new Security Domain)" );
            }

            try {
                createAdminCertificate(request, response, context);
            } catch (IOException e) {
                CMS.debug("AdminPanel update: Exception: " + e.toString());
                context.put("errorString",
                        "Failed to create administrator certificate.");
                throw e;
            }
        } else {
            String ca_hostname = null;
            int ca_port = -1;

            // REMINDER:  This panel is NOT used by "clones"
            if( subsystemtype.equals( "CA" ) ) {
                if( selected_hierarchy.equals( "root" ) ) {
                    CMS.debug( "AdminPanel update:  "
                             + "Root CA subsystem - "
                             + "(existing Security Domain)" );
                } else {
                    CMS.debug( "AdminPanel update:  "
                             + "Subordinate CA subsystem - "
                             + "(existing Security Domain)" );
                }
            } else {
                CMS.debug( "AdminPanel update:  "
                         + subsystemtype
                         + " subsystem" );
            }

            if (type.equals("sdca")) {
                try {
                    ca_hostname = config.getString("preop.ca.hostname");
                    ca_port = config.getInteger("preop.ca.httpsport");
                } catch (Exception e) {
                }
            } else {
                try {
                    ca_hostname = config.getString("securitydomain.host", "");
                    ca_port = config.getInteger("securitydomain.httpseeport");
                } catch (Exception e) {
                }
            }

            submitRequest(ca_hostname, ca_port, request, response, context);
        }

        try {
            CMS.reinit(IUGSubsystem.ID);
        } catch (Exception e) {
            CMS.debug("AdminPanel update: " + e.toString());
        }

        try {
            config.commit(false);
        } catch (Exception e) {}
    
    }

    private void createAdmin(HttpServletRequest request) throws IOException {
        IUGSubsystem system = (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));
        IConfigStore config = CMS.getConfigStore();
        String adminName = null;
        String groupName = null;

        try {
            adminName = config.getString(PRE_CONF_ADMIN_NAME,
                    "Certificate System Administrator");
            groupName = config.getString(PRE_CONF_AGENT_GROUP,
                    "Certificate Manager Agents");
        } catch (Exception e) {
            CMS.debug("AdminPanel createAdmin: " + e.toString());
        }

        IUser user = null;
        String uid = HttpInput.getUID(request, "uid");

        try {
            user = system.createUser(uid);
            String email = HttpInput.getEmail(request, "email");
            String name = HttpInput.getName(request, "name");
            String pwd = HttpInput.getPassword(request, "__pwd");

            user.setEmail(email);
            user.setPassword(pwd);
            user.setFullName(name);
            user.setUserType("adminType");
            user.setState("1");
            user.setPhone("");
            system.addUser(user);
        } catch (LDAPException e) {
            CMS.debug("AdminPanel createAdmin: addUser " + e.toString());
            if (e.getLDAPResultCode() != LDAPException.ENTRY_ALREADY_EXISTS) {
                throw new IOException(e.toString());
            }
        } catch (Exception e) {
            CMS.debug("AdminPanel createAdmin: addUser " + e.toString());
            throw new IOException(e.toString());
        }

        IGroup group = null;

        try {
            group = system.getGroupFromName(groupName);
            if (!group.isMember(uid)) {
                group.addMemberName(uid);
                system.modifyGroup(group);
            }
            group = system.getGroupFromName("Administrators");
            if (!group.isMember(uid)) {
                group.addMemberName(uid);
                system.modifyGroup(group);
            }

            String select = config.getString("securitydomain.select", "");
            if (select.equals("new")) {
                group = system.getGroupFromName("Security Domain Administrators");
                if (!group.isMember(uid)) {
                    group.addMemberName(uid);
                    system.modifyGroup(group);
                }

                group = system.getGroupFromName("Enterprise CA Administrators");
                if (!group.isMember(uid)) {
                    group.addMemberName(uid);
                    system.modifyGroup(group);
                }

                group = system.getGroupFromName("Enterprise KRA Administrators");
                if (!group.isMember(uid)) {
                    group.addMemberName(uid);
                    system.modifyGroup(group);
                }

                group = system.getGroupFromName("Enterprise RA Administrators");
                if (!group.isMember(uid)) {
                    group.addMemberName(uid);
                    system.modifyGroup(group);
                }

                group = system.getGroupFromName("Enterprise TKS Administrators");
                if (!group.isMember(uid)) {
                    group.addMemberName(uid);
                    system.modifyGroup(group);
                }

                group = system.getGroupFromName("Enterprise OCSP Administrators");
                if (!group.isMember(uid)) {
                    group.addMemberName(uid);
                    system.modifyGroup(group);
                }

                group = system.getGroupFromName("Enterprise TPS Administrators");
                if (!group.isMember(uid)) {
                    group.addMemberName(uid);
                    system.modifyGroup(group);
                }
            }
        } catch (Exception e) {
            CMS.debug("AdminPanel createAdmin: modifyGroup " + e.toString());
            throw new IOException(e.toString());
        }
    }

    private void submitRequest(String ca_hostname, int ca_port, HttpServletRequest request,
            HttpServletResponse response, Context context) throws IOException {
        IConfigStore config = CMS.getConfigStore();
        String sd_hostname = null;
        int sd_port = -1;

        try {
            sd_hostname = config.getString("securitydomain.host", "");
            sd_port = config.getInteger("securitydomain.httpseeport");
        } catch (Exception e) {}

        String profileId = HttpInput.getID(request, "profileId");
        if (profileId == null) {
            try {
                profileId = config.getString("preop.admincert.profile", "caAdminCert");
            } catch (Exception e) {}
        }

        String cert_request_type = HttpInput.getID(request, "cert_request_type");
        String cert_request = HttpInput.getCertRequest(request, "cert_request");
        cert_request = URLEncoder.encode(cert_request, "UTF-8");
        String session_id = CMS.getConfigSDSessionId();
        String subjectDN = HttpInput.getString(request, "subject");

        String content = "profileId="+profileId+"&cert_request_type="+cert_request_type+"&cert_request="+cert_request+"&xmlOutput=true&sessionID="+session_id+"&subject="+subjectDN;

        HttpClient httpclient = new HttpClient();
        String c = null;

        try {
            JssSSLSocketFactory factory = new JssSSLSocketFactory();

            httpclient = new HttpClient(factory);
            httpclient.connect(ca_hostname, ca_port);
            HttpRequest httprequest = new HttpRequest();
            httprequest.setMethod(HttpRequest.POST);
            httprequest.setURI("/ca/ee/ca/profileSubmit");
            httprequest.setHeader("user-agent", "HTTPTool/1.0");

            httprequest.setHeader("content-length", "" + content.length());
            httprequest.setHeader("content-type",
                    "application/x-www-form-urlencoded");
            httprequest.setContent(content);
            HttpResponse httpresponse = httpclient.send(httprequest);

            c = httpresponse.getContent();
            CMS.debug("AdminPanel submitRequest: content=" + c);
            
            // retrieve the request Id ad admin certificate
            if (c != null) {
                try {
                    ByteArrayInputStream bis = new ByteArrayInputStream(
                            c.getBytes());
                    XMLObject parser = null;

                    try {
                        parser = new XMLObject(bis);
                    } catch (Exception e) {
                        CMS.debug( "AdminPanel::submitRequest() - "
                                 + "Exception="+e.toString() );
                        throw new IOException( e.toString() );
                    }
                    String status = parser.getValue("Status");

                    CMS.debug("AdminPanel update: status=" + status);
                    if (status.equals("2")) {
                        //relogin to the security domain
                        reloginSecurityDomain(response);
                        return;
                    } else if (!status.equals("0")) {
                        String error = parser.getValue("Error");

                        context.put("errorString", error);
                        throw new IOException(error);
                    }
 
                    IConfigStore cs = CMS.getConfigStore();
                    String id = parser.getValue("Id");

                    cs.putString("preop.admincert.requestId.0", id);
                    String serial = parser.getValue("serialno");

                    cs.putString("preop.admincert.serialno.0", serial);
                    String b64 = parser.getValue("b64");
                    String instanceRoot = cs.getString("instanceRoot", "");
                    String dir = instanceRoot + File.separator + "conf"
                            + File.separator + "admin.b64";

                    cs.putString("preop.admincert.b64", dir);
                    PrintStream ps = new PrintStream(new FileOutputStream(dir)); 

                    ps.println(b64);
                    ps.flush();
                    ps.close();
                } catch (IOException ee) {
                    context.put("errorString", ee.toString());
                    throw ee;
                } catch (Exception ee) {
                    context.put("errorString", ee.toString());
                    throw new IOException(ee.toString());
                }
            }
        } catch (Exception e) {
            CMS.debug("AdminPanel submitRequest: " + e.toString());
        }
    }

    private void createAdminCertificate(HttpServletRequest request,
            HttpServletResponse response, Context context) throws IOException {
        String cert_request = HttpInput.getCertRequest(request, "cert_request");

        String cert_request_type = HttpInput.getID(request, "cert_request_type");
        IConfigStore cs = CMS.getConfigStore();

        if( cs == null ) {
            CMS.debug( "AdminPanel::createAdminCertificate() - cs is null!" );
            throw new IOException( "cs is null" );
        }

        String subject = "";
        X509Key x509key = null;
        if (cert_request_type.equals("crmf")) {
            try {
                byte[] b = CMS.AtoB(cert_request);
                SEQUENCE crmfMsgs = CryptoUtil.parseCRMFMsgs(b);
                subject = CryptoUtil.getSubjectName(crmfMsgs);
                x509key = CryptoUtil.getX509KeyFromCRMFMsgs(crmfMsgs);
            } catch (Exception e) {
                CMS.debug(
                        "AdminPanel createAdminCertificate: Exception="
                                + e.toString());
            }
        // this request is from IE. The VBScript has problem of generating
        // certificate request if the subject name has E and UID components.
        // For now, we always hardcoded the subject DN to be cn=NAME in 
        // the IE browser.
        } else if (cert_request_type.equals("pkcs10")) {
            try {
                byte[] b = CMS.AtoB(cert_request);
                PKCS10 pkcs10 = new PKCS10(b);
                subject = request.getParameter("subject");
                x509key = pkcs10.getSubjectPublicKeyInfo();
            } catch (Exception e) {
                CMS.debug("AdminPanel createAdminCertificate: Exception="
                  + e.toString());
            }
        }

        if( x509key == null ) {
            CMS.debug( "AdminPanel::createAdminCertificate() - x509key is null!" );
            throw new IOException( "x509key is null" );
        }

        try {
            cs.putString(PCERT_PREFIX + CERT_TAG + ".dn", subject);
            String caType = cs.getString(PCERT_PREFIX + CERT_TAG + ".type", "local");
            X509CertImpl impl = CertUtil.createLocalCert(cs, x509key,
              PCERT_PREFIX, CERT_TAG, caType, context);

            // update the locally created request for renewal
            CertUtil.updateLocalRequest(cs, CERT_TAG, cert_request,cert_request_type, subject);

            ISubsystem ca = (ISubsystem) CMS.getSubsystem("ca");
            if (ca != null) {
                createPKCS7(impl);
            }
            cs.putString("preop.admincert.serialno.0",
              impl.getSerialNumber().toString(16));
        } catch (Exception e) {
            CMS.debug("AdminPanel createAdminCertificate: Exception="
              + e.toString());
        }
    }

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {

        context.put("title", "Administrator");
        context.put("panel", "admin/console/config/adminpanel.vm");
        ISubsystem ca = (ISubsystem) CMS.getSubsystem("ca");
        IConfigStore cs = CMS.getConfigStore();
        String type = "";
        String info = "";

        try {
            type = cs.getString("preop.ca.type", "");
        } catch (Exception e) {}
        if (ca == null && type.equals("otherca")) { 
            info = "Since you do not join the Redhat CA network, the administrator's certificate will not be generated automatically.";
        }
        context.put("info", info);
        context.put("admin_email", request.getParameter("email"));
        context.put("admin_name", request.getParameter("name"));
        context.put("admin_pwd", "");
        context.put("admin_pwd_again", "");
        context.put("admin_uid", request.getParameter("uid"));
    }

    public boolean shouldSkip() {
        try {
            IConfigStore c = CMS.getConfigStore();
            String s = c.getString("preop.subsystem.select",null);
            if (s != null && s.equals("clone")) {
                return true;
            }
        } catch (EBaseException e) {
        }

        return false;
    }


    private void createPKCS7(X509CertImpl cert) {
        try {
            IConfigStore cs = CMS.getConfigStore();
            ICertificateAuthority ca = (ICertificateAuthority)CMS.getSubsystem("ca");
            CertificateChain cachain = ca.getCACertChain();
            X509Certificate[] cacerts = cachain.getChain();
            X509CertImpl[] userChain = new X509CertImpl[cacerts.length + 1];
            int m = 1, n = 0;

            for (; n < cacerts.length; m++, n++) {
                userChain[m] = (X509CertImpl) cacerts[n];
            }

            userChain[0] = cert;
            PKCS7 p7 = new PKCS7(new AlgorithmId[0],
              new ContentInfo(new byte[0]), userChain, new SignerInfo[0]);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            p7.encodeSignedData(bos);
            byte[] p7Bytes = bos.toByteArray();
            String p7Str = CMS.BtoA(p7Bytes);
            cs.putString("preop.admincert.pkcs7", CryptoUtil.normalizeCertStr(p7Str));
        } catch (Exception e) {
            CMS.debug("AdminPanel createPKCS7: Failed to create pkcs7 file. Exception: "+e.toString());
        }
    }
}
