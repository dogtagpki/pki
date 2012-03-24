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


import org.apache.velocity.context.Context;
import javax.servlet.http.*;
import javax.servlet.*;
import java.io.*;
import java.util.*;
import java.net.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.base.*;
import com.netscape.cms.servlet.wizard.*;
import com.netscape.cms.servlet.base.*;
import org.mozilla.jss.*;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.crypto.*;
import org.mozilla.jss.util.Base64OutputStream;
import org.mozilla.jss.pkcs11.*;
import netscape.security.x509.*;
import com.netscape.cmsutil.xml.*;
import com.netscape.cmsutil.http.*;
import org.w3c.dom.*;
import org.xml.sax.*;
import java.security.cert.*;
import java.security.*;
import netscape.ldap.*;

import com.netscape.cmsutil.crypto.*;
import com.netscape.cms.servlet.wizard.*;

public class WizardPanelBase implements IWizardPanel {
    public static String PCERT_PREFIX = "preop.cert.";
    public static String SUCCESS = "0";
    public static String FAILURE = "1";
    public static String AUTH_FAILURE = "2";

    /**
     * Definition for static variables in CS.cfg
     */
    public static final String CONF_CA_CERT = "ca.signing.cert";
    public static final String CONF_CA_CERTREQ = "ca.signing.certreq";
    public static final String CONF_CA_CERTNICKNAME = "ca.signing.certnickname";

    public static final String PRE_CONF_ADMIN_NAME = "preop.admin.name";
    public static final String PRE_CONF_AGENT_GROUP = "preop.admin.group";

    /**
     * Definition for "preop" static variables in CS.cfg
     * -- "preop" config parameters should not assumed to exist after configuation
     */

    public static final String PRE_CONF_CA_TOKEN = "preop.module.token";
    public static final String PRE_CA_TYPE = "preop.ca.type";
    public static final String PRE_OTHER_CA = "otherca";
    public static final String PRE_ROOT_CA = "rootca";

    private String mName = null;
    private int mPanelNo = 0;
    private String mId = null;

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException 
    {
        mPanelNo = panelno;
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id) 
        throws ServletException 
    {
        mPanelNo = panelno;
    }

    /**
     * Cleans up this panel so that isPanelDone() will return false.
     */
    public void cleanUp() throws IOException {
    }

    public String getName() {
        return mName;
    }

    public int getPanelNo() {
        return mPanelNo;
    }

    public void setPanelNo(int num) {
        mPanelNo = num;
    }

    public void setName(String name) {
        mName = name;
    }

    public void setId(String id) {
        mId = id;
    }

    public String getId() {
        return mId;
    }

    public PropertySet getUsage() {
        PropertySet set = null;

        return set;
    }
   
    /**
     * Should we skip this panel?
     */
    public boolean shouldSkip() {
        return false;
    }

    /**
     * Is this panel done
     */
    public boolean isPanelDone() {
        return false;
    }

    /**
     * Show "Apply" button on frame?
     */
    public boolean showApplyButton() {
        return false;
    }

    /**
     * Is this a subPanel?
     */
    public boolean isSubPanel() {
        return false;
    }

    public boolean isLoopbackPanel() {
        return false;
    }

    /**
     * has subPanels?
     */
    public boolean hasSubPanel() {
        return false;
    }

    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {}

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
            Context context) throws IOException {}

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {}

    /**
     * Retrieves locale based on the request.
     */
    public Locale getLocale(HttpServletRequest req) {
        Locale locale = null;
        String lang = req.getHeader("accept-language");

        if (lang == null) {
            // use server locale
            locale = Locale.getDefault();
        } else {
            locale = new Locale(UserInfo.getUserLanguage(lang),
                    UserInfo.getUserCountry(lang));
        }
        return locale;
    }

    public String getNickname(IConfigStore config, String certTag) {
        String instanceID = "";

        try {
            instanceID = config.getString("instanceId", "");
        } catch (Exception e) {}

        String nickname = certTag + "Cert cert-" + instanceID;
        String preferredNickname = null;

        try {
            preferredNickname = config.getString(
                    PCERT_PREFIX + certTag + ".nickname", null);
        } catch (Exception e) {}

        if (preferredNickname != null) {
            nickname = preferredNickname;
        }
        return nickname;
    }

    public void updateDomainXML(String hostname, int port, boolean https,
      String servlet, String uri) throws IOException {
        CMS.debug("WizardPanelBase updateDomainXML start hostname=" + hostname + " port=" + port);
        IConfigStore cs = CMS.getConfigStore();
        String nickname = "";
        String tokenname = "";
        try {
            nickname = cs.getString("preop.cert.subsystem.nickname", "");
            tokenname = cs.getString("preop.module.token", "");
        } catch (Exception e) {}

        if (!tokenname.equals("") &&
            !tokenname.equals("Internal Key Storage Token") &&
            !tokenname.equals("internal")) {
              nickname = tokenname+":"+nickname;
        }

        CMS.debug("WizardPanelBase updateDomainXML nickname=" + nickname);
        CMS.debug("WizardPanelBase: start sending updateDomainXML request");
        String c = getHttpResponse(hostname, port, https, servlet, uri, nickname); 
        CMS.debug("WizardPanelBase: done sending updateDomainXML request");

        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject obj = null;
                try {
                    obj = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase::updateDomainXML() - "
                             + "Exception="+e.toString() );
                    throw new IOException( e.toString() );
                }

                String status = obj.getValue("Status");
                CMS.debug("WizardPanelBase updateDomainXML: status=" + status);

                if (status.equals(SUCCESS)) {
                    return;
                } else {
                    String error = obj.getValue("Error");
                    throw new IOException(error);
                } 
            } catch (IOException e) {
                CMS.debug("WizardPanelBase: updateDomainXML: " + e.toString());
                throw e;
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: updateDomainXML: " + e.toString());
                throw new IOException(e.toString());
            }
        }
    }

    public int getSubsystemCount( String hostname, int https_admin_port,
                                  boolean https, String type )
                                  throws IOException {
        CMS.debug("WizardPanelBase getSubsystemCount start");
        String c = getDomainXML(hostname, https_admin_port, true);
        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject obj = new XMLObject(bis);
                String containerName = type+"List";
                Node n = obj.getContainer(containerName);
                NodeList nlist = n.getChildNodes();
                String countS = "";
                for (int i=0; i<nlist.getLength(); i++) {
                    Element nn = (Element)nlist.item(i);
                    String tagname = nn.getTagName();
                    if (tagname.equals("SubsystemCount")) {
                        NodeList nlist1 = nn.getChildNodes();
                        Node nn1 = nlist1.item(0);
                        countS = nn1.getNodeValue();
                        break;
                    }
                }
                CMS.debug("WizardPanelBase getSubsystemCount: SubsystemCount="+countS);
                int num = 0;

                if (countS != null && !countS.equals("")) {
                    try {
                        num = Integer.parseInt(countS);
                    } catch (Exception ee) {
                    }
                }

                return num;
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: getSubsystemCount: "+e.toString());
                throw new IOException(e.toString());
            }
        }

        return -1;
    }

    public String getDomainXML( String hostname, int https_admin_port,
                               boolean https ) 
                               throws IOException {
        CMS.debug("WizardPanelBase getDomainXML start");
        String c = getHttpResponse( hostname, https_admin_port, https,
                                    "/ca/admin/ca/getDomainXML", null, null );
        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase::getDomainXML() - "
                             + "Exception="+e.toString() );
                    throw new IOException( e.toString() );
                }

                String status = parser.getValue("Status");

                CMS.debug("WizardPanelBase getDomainXML: status=" + status);

                if (status.equals(SUCCESS)) {
                    String domainInfo = parser.getValue("DomainInfo");

                    CMS.debug(
                            "WizardPanelBase getDomainXML: domainInfo="
                                    + domainInfo);
                    return domainInfo; 
                } else {
                    String error = parser.getValue("Error");

                    throw new IOException(error);
                } 
            } catch (IOException e) {
                CMS.debug("WizardPanelBase: getDomainXML: " + e.toString());
                throw e;
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: getDomainXML: " + e.toString());
                throw new IOException(e.toString());
            }
        }

        return null;
    }

    public String getSubsystemCert(String host, int port, boolean https) 
      throws IOException {
        CMS.debug("WizardPanelBase getSubsystemCert start");
        String c = getHttpResponse(host, port, https, 
          "/ca/admin/ca/getSubsystemCert", null, null);
        if (c != null) {
            try {
                ByteArrayInputStream bis = 
                  new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;
                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase::getSubsystemCert() - "
                             + "Exception="+e.toString() );
                    throw new IOException( e.toString() );
                }
                String status = parser.getValue("Status");
                if (status.equals(SUCCESS)) {
                    String s = parser.getValue("Cert");
                    return s;
                } else
                    return null; 
            } catch (Exception e) {
            }
        }

        return null;
    }

    public void updateConnectorInfo(String host, int port, boolean https,
      String content) throws IOException {
        CMS.debug("WizardPanelBase updateConnectorInfo start");
        String c = getHttpResponse(host, port, https, 
          "/ca/admin/ca/updateConnector", content, null);
        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase::updateConnectorInfo() - "
                             + "Exception="+e.toString() );
                    throw new IOException( e.toString() );
                }

                String status = parser.getValue("Status");

                CMS.debug("WizardPanelBase updateConnectorInfo: status=" + status);

                if (!status.equals(SUCCESS)) {
                    String error = parser.getValue("Error");
                    throw new IOException(error);
                } 
            } catch (IOException e) {
                CMS.debug("WizardPanelBase: updateConnectorInfo: " + e.toString());
                throw e;
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: updateConnectorInfo: " + e.toString());
                throw new IOException(e.toString());
            }
        }
    }

    public String getCertChainUsingSecureAdminPort( String hostname,
                                                    int https_admin_port,
                                                    boolean https,
                                                    ConfigCertApprovalCallback
                                                    certApprovalCallback )
                                                    throws IOException {
        CMS.debug("WizardPanelBase getCertChainUsingSecureAdminPort start");
        String c = getHttpResponse( hostname, https_admin_port, https,
                                    "/ca/admin/ca/getCertChain", null, null,
                                    certApprovalCallback );

        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase::getCertChainUsingSecureAdminPort() - "
                             + "Exception="+e.toString() );
                    throw new IOException( e.toString() );
                }

                String status = parser.getValue("Status");

                CMS.debug("WizardPanelBase getCertChainUsingSecureAdminPort: status=" + status);

                if (status.equals(SUCCESS)) {
                    String certchain = parser.getValue("ChainBase64");

                    certchain = CryptoUtil.normalizeCertStr(certchain);
                    CMS.debug(
                            "WizardPanelBase getCertChainUsingSecureAdminPort: certchain="
                                    + certchain);
                    return certchain; 
                } else {
                    String error = parser.getValue("Error");

                    throw new IOException(error);
                } 
            } catch (IOException e) {
                CMS.debug("WizardPanelBase: getCertChainUsingSecureAdminPort: " + e.toString());
                throw e;
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: getCertChainUsingSecureAdminPort: " + e.toString());
                throw new IOException(e.toString());
            }
        }

        return null;
    }

    public String getCertChainUsingSecureEEPort( String hostname,
                                                 int https_ee_port,
                                                 boolean https,
                                                 ConfigCertApprovalCallback
                                                 certApprovalCallback )
                                                 throws IOException {
        CMS.debug("WizardPanelBase getCertChainUsingSecureEEPort start");
        String c = getHttpResponse( hostname, https_ee_port, https,
                                    "/ca/ee/ca/getCertChain", null, null,
                                    certApprovalCallback );

        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase::getCertChainUsingSecureEEPort() - "
                             + "Exception="+e.toString() );
                    throw new IOException( e.toString() );
                }

                String status = parser.getValue("Status");

                CMS.debug("WizardPanelBase getCertChainUsingSecureEEPort: status=" + status);

                if (status.equals(SUCCESS)) {
                    String certchain = parser.getValue("ChainBase64");

                    certchain = CryptoUtil.normalizeCertStr(certchain);
                    CMS.debug(
                            "WizardPanelBase getCertChainUsingSecureEEPort: certchain="
                                    + certchain);
                    return certchain; 
                } else {
                    String error = parser.getValue("Error");

                    throw new IOException(error);
                } 
            } catch (IOException e) {
                CMS.debug("WizardPanelBase: getCertChainUsingSecureEEPort: " + e.toString());
                throw e;
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: getCertChainUsingSecureEEPort: " + e.toString());
                throw new IOException(e.toString());
            }
        }

        return null;
    }

    public boolean updateConfigEntries(String hostname, int port, boolean https,
      String servlet, String uri, IConfigStore config, 
      HttpServletResponse response) throws IOException {
        CMS.debug("WizardPanelBase updateConfigEntries start");
        String c = getHttpResponse(hostname, port, https, servlet, uri, null);

        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase::updateConfigEntries() - "
                             + "Exception="+e.toString() );
                    throw new IOException( e.toString() );
                }

                String status = parser.getValue("Status");

                CMS.debug("WizardPanelBase updateConfigEntries: status=" + status);

                if (status.equals(SUCCESS)) {
                    String cstype = "";
                    try {
                        cstype = config.getString("cs.type", "");
                    } catch (Exception e) {
                        CMS.debug("WizardPanelBase::updateConfigEntries() - unable to get cs.type: " + e.toString());
                    }
              
                    Document doc = parser.getDocument(); 
                    NodeList list = doc.getElementsByTagName("name");
                    int len = list.getLength();
                    for (int i=0; i<len; i++) {
                        Node n = list.item(i);
                        NodeList nn = n.getChildNodes();
                        String name = nn.item(0).getNodeValue();
                        Node parent = n.getParentNode();
                        nn = parent.getChildNodes();
                        int len1 = nn.getLength();
                        String v = "";
                        for (int j=0; j<len1; j++) {
                            Node nv = nn.item(j);
                            String val = nv.getNodeName();
                            if (val.equals("value")) {
                                NodeList n2 = nv.getChildNodes();
                                if (n2.getLength() > 0)
                                    v = n2.item(0).getNodeValue(); 
                                break;    
                            }
                        }

                        if (name.equals("internaldb.basedn")) {
                            config.putString(name, v);
                            config.putString("preop.internaldb.master.basedn", v);
                        } else if (name.startsWith("internaldb")) {
                            config.putString(name.replaceFirst("internaldb", "preop.internaldb.master"), v);
                        } else if (name.equals("instanceId")) {
                            config.putString("preop.master.instanceId", v);
                        } else if (name.equals("cloning.cert.signing.nickname")) {
                            config.putString("preop.master.signing.nickname", v);
                            config.putString("preop.cert.signing.nickname", v);
                        } else if (name.equals("cloning.ocsp_signing.nickname")) {
                            config.putString("preop.master.ocsp_signing.nickname", v);
                            config.putString("preop.cert.ocsp_signing.nickname", v);
                        } else if (name.equals("cloning.subsystem.nickname")) {
                            config.putString("preop.master.subsystem.nickname", v);
                            config.putString("preop.cert.subsystem.nickname", v);
                        } else if (name.equals("cloning.transport.nickname")) {
                            config.putString("preop.master.transport.nickname", v);
                            config.putString("kra.transportUnit.nickName", v);
                            config.putString("preop.cert.transport.nickname", v);
                        } else if (name.equals("cloning.storage.nickname")) {
                            config.putString("preop.master.storage.nickname", v);
                            config.putString("kra.storageUnit.nickName", v);
                            config.putString("preop.cert.storage.nickname", v);
                        } else if  (name.equals("cloning.audit_signing.nickname")) {
                            config.putString("preop.master.audit_signing.nickname", v);
                            config.putString("preop.cert.audit_signing.nickname", v);
                            config.putString(name, v);
                        } else if (name.startsWith("cloning.ca")) {
                            config.putString(name.replaceFirst("cloning", "preop"), v);
                        } else if (name.equals("cloning.signing.keyalgorithm")) {
                            config.putString(name.replaceFirst("cloning", "preop.cert"), v);
                            if (cstype.equals("CA")) {
                                config.putString("ca.crl.MasterCRL.signingAlgorithm", v);
                                config.putString("ca.signing.defaultSigningAlgorithm", v);
                            } else if (cstype.equals("OCSP")) {
                                config.putString("ocsp.signing.defaultSigningAlgorithm", v);
                            }
                        } else if (name.equals("cloning.transport.keyalgorithm")) {
                            config.putString(name.replaceFirst("cloning", "preop.cert"), v);
                            config.putString("kra.transportUnit.signingAlgorithm", v);
                        } else if (name.equals("cloning.ocsp_signing.keyalgorithm")) {
                            config.putString(name.replaceFirst("cloning", "preop.cert"), v);
                            if (cstype.equals("CA")) {
                                config.putString("ca.ocsp_signing.defaultSigningAlgorithm", v);
                            }
                        } else if (name.startsWith("cloning")) {
                            config.putString(name.replaceFirst("cloning", "preop.cert"), v);
                        } else {
                            config.putString(name, v);
                        }
                    }

                    // set master ldap password (if it exists) temporarily in password store
                    // in case it is needed for replication.  Not stored in password.conf.
                    try {
                        String master_pwd = config.getString("preop.internaldb.master.ldapauth.password", "");
                        if (!master_pwd.equals("")) {
                            config.putString("preop.internaldb.master.ldapauth.bindPWPrompt", "master_internaldb");
                            String passwordFile = config.getString("passwordFile");
                            IConfigStore psStore = CMS.createFileConfigStore(passwordFile);
                            psStore.putString("master_internaldb", master_pwd);
                            psStore.commit(false);
                        }
                    } catch (Exception e) {
                        CMS.debug("updateConfigEntries: Failed to temporarily store master bindpwd: " + e.toString());
                        e.printStackTrace();
                        throw new IOException(e.toString());
                    }

                    return true;
                } else if (status.equals(AUTH_FAILURE)) {
                    reloginSecurityDomain(response);
                    return false;
                } else {
                    String error = parser.getValue("Error");

                    throw new IOException(error);
                } 
            } catch (IOException e) {
                CMS.debug("WizardPanelBase: updateConfigEntries: " + e.toString());
                throw e;
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: updateConfigEntries: " + e.toString());
                throw new IOException(e.toString());
            }
        }

        return false;
    }

    public boolean authenticate(String hostname, int port, boolean https,
            String servlet, String uri) throws IOException {
        CMS.debug("WizardPanelBase authenticate start");
        String c = getHttpResponse(hostname, port, https, servlet, uri, null);
        IConfigStore cs = CMS.getConfigStore();

        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase::authenticate() - "
                             + "Exception="+e.toString() );
                    throw new IOException( e.toString() );
                }

                String status = parser.getValue("Status");

                CMS.debug("WizardPanelBase authenticate: status=" + status);

                if (status.equals(SUCCESS)) {
                    String cookie = parser.getValue("Cookie");
                    cs.putString("preop.cookie", cookie);
                    return true;
                } else {
                    String error = parser.getValue("Error");
                    return false;
                } 
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: authenticate: " + e.toString());
                throw new IOException(e.toString());
            }
        }

        return false;
    }

    public void updateOCSPConfig(String hostname, int port, boolean https, 
        String content, HttpServletResponse response) 
      throws IOException {
        CMS.debug("WizardPanelBase updateOCSPConfig start");
        String c = getHttpResponse(hostname, port, https, 
          "/ca/ee/ca/updateOCSPConfig", content, null);
        if (c == null || c.equals("")) {
            CMS.debug("WizardPanelBase updateOCSPConfig: content is null.");
            throw new IOException("The server you want to contact is not available");
        } else {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase::updateOCSPConfig() - "
                             + "Exception="+e.toString() );
                    throw new IOException( e.toString() );
                }

                String status = parser.getValue("Status");

                CMS.debug("WizardPanelBase updateOCSPConfig: status=" + status);

                if (status.equals(SUCCESS)) {
                    CMS.debug("WizardPanelBase updateOCSPConfig: Successfully update the OCSP configuration in the CA.");
                } else if (status.equals(AUTH_FAILURE)) {
                    reloginSecurityDomain(response);
                    return;
                } else {
                    String error = parser.getValue("Error");

                    throw new IOException(error);
                } 
            } catch (IOException e) {
                CMS.debug("WizardPanelBase updateOCSPConfig: " + e.toString());
                throw e;
            } catch (Exception e) {
                CMS.debug("WizardPanelBase updateOCSPConfig: " + e.toString());
                throw new IOException(e.toString());
            }
        }
    }

    public void updateNumberRange(String hostname, int port, boolean https, 
        String content, String type, HttpServletResponse response) 
      throws IOException {
        CMS.debug("WizardPanelBase updateNumberRange start host=" + hostname + 
                                " port=" + port);
        IConfigStore cs = CMS.getConfigStore();
        String cstype = "";
        try {
            cstype = cs.getString("cs.type", "");
        } catch (Exception e) {
        }

        cstype = toLowerCaseSubsystemType(cstype);
        String c = getHttpResponse(hostname, port, https, 
          "/"+cstype+"/ee/"+cstype+"/updateNumberRange", content, null);
        if (c == null || c.equals("")) {
            CMS.debug("WizardPanelBase updateNumberRange: content is null.");
            throw new IOException("The server you want to contact is not available");
        } else {
            CMS.debug("content="+c);
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase::updateNumberRange() - "
                             + "Exception="+e.toString() );
                    throw new IOException( e.toString() );
                }

                String status = parser.getValue("Status");

                CMS.debug("WizardPanelBase updateNumberRange: status=" + status);
                if (status.equals(SUCCESS)) {
                    String beginNum = parser.getValue("beginNumber");
                    String endNum = parser.getValue("endNumber");
                    if (type.equals("request")) {
                        cs.putString("dbs.beginRequestNumber", beginNum);
                        cs.putString("dbs.endRequestNumber", endNum);
                    } else if (type.equals("serialNo")) {
                        cs.putString("dbs.beginSerialNumber", beginNum);
                        cs.putString("dbs.endSerialNumber", endNum);
                    } else if (type.equals("replicaId")) {
                        cs.putString("dbs.beginReplicaNumber", beginNum);
                        cs.putString("dbs.endReplicaNumber", endNum);
                    }
                    // enable serial number management in clone
                    cs.putString("dbs.enableSerialManagement", "true");
                    cs.commit(false);
                } else if (status.equals(AUTH_FAILURE)) {
                    reloginSecurityDomain(response);
                    return;
                } else {
                    String error = parser.getValue("Error");

                    throw new IOException(error);
                } 
            } catch (IOException e) {
                CMS.debug("WizardPanelBase: updateNumberRange: " + e.toString());
                CMS.debug(e);
                throw e;
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: updateNumberRange: " + e.toString());
                CMS.debug(e);
                throw new IOException(e.toString());
            }
        }
    }

    public int getPort(String hostname, int port, boolean https, 
            String portServlet, boolean sport) 
        throws IOException {
        CMS.debug("WizardPanelBase getPort start");
        String c = getHttpResponse(hostname, port, https, portServlet,
                "secure=" + sport, null);

        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase::getPort() - "
                             + "Exception="+e.toString() );
                    throw new IOException( e.toString() );
                }

                String status = parser.getValue("Status");

                CMS.debug("WizardPanelBase getPort: status=" + status);

                if (status.equals(SUCCESS)) {
                    String portStr = parser.getValue("Port");

                    port = Integer.parseInt(portStr);
                    return port;
                } else {
                    String error = parser.getValue("Error");

                    throw new IOException(error);
                } 
            } catch (IOException e) {
                CMS.debug("WizardPanelBase: getPort: " + e.toString());
                throw e;
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: getPort: " + e.toString());
                throw new IOException(e.toString());
            }
        }

        return -1;
    }

    public String getHttpResponse(String hostname, int port, boolean secure,
      String uri, String content, String clientnickname) throws IOException {
        return getHttpResponse(hostname, port, secure, uri, content, clientnickname, null);
    }

    public String getHttpResponse(String hostname, int port, boolean secure, 
      String uri, String content, String clientnickname, 
      SSLCertificateApprovalCallback certApprovalCallback) 
      throws IOException {
        HttpClient httpclient = null;
        String c = null;

        try {
            if (secure) {
                JssSSLSocketFactory factory = null;
                if (clientnickname != null && clientnickname.length() > 0)
                    factory = new JssSSLSocketFactory(clientnickname);
                else
                    factory = new JssSSLSocketFactory();

                httpclient = new HttpClient(factory, certApprovalCallback);
            } else {
                httpclient = new HttpClient();
            }
            httpclient.connect(hostname, port);
            HttpRequest httprequest = new HttpRequest();

            httprequest.setMethod(HttpRequest.POST);
            httprequest.setURI(uri);
            // httprequest.setURI("/ca/ee/ca/ports");
            httprequest.setHeader("user-agent", "HTTPTool/1.0");
            // String content_c = "secure="+secure;
            httprequest.setHeader("content-type",
                    "application/x-www-form-urlencoded");
            if (content != null && content.length() > 0) {
                String content_c = content;

                httprequest.setHeader("content-length", "" + content_c.length());
                httprequest.setContent(content_c);
            }
            HttpResponse httpresponse = httpclient.send(httprequest);

            c = httpresponse.getContent();
        } catch (ConnectException e) {
            CMS.debug("WizardPanelBase getHttpResponse: " + e.toString());
            throw new IOException("The server you tried to contact is not running.");
        } catch (Exception e) {
            CMS.debug("WizardPanelBase getHttpResponse: " + e.toString());
            throw new IOException(e.toString());
        } finally {
            if (httpclient.connected()) {
                httpclient.disconnect();
            }
        }

        return c;
    }

    public boolean isSDHostDomainMaster (IConfigStore config) {
        String dm="false";
        try {
            String hostname = config.getString("securitydomain.host");
            int httpsadminport = config.getInteger("securitydomain.httpsadminport");

            CMS.debug("Getting domain.xml from CA...");
            String c = getDomainXML(hostname, httpsadminport, true);

            CMS.debug("Getting DomainMaster from security domain");

            ByteArrayInputStream bis = new ByteArrayInputStream( c.getBytes() );
            XMLObject parser = new XMLObject( bis );
            Document doc = parser.getDocument();
            NodeList nodeList = doc.getElementsByTagName( "CA" );

            int len = nodeList.getLength();
            for( int i = 0; i < len; i++ ) {
                Vector v_hostname =
                       parser.getValuesFromContainer( nodeList.item(i),
                                                      "Host" );

                Vector v_https_admin_port =
                       parser.getValuesFromContainer( nodeList.item(i),
                                                      "SecureAdminPort" );

                Vector v_domain_mgr =
                       parser.getValuesFromContainer( nodeList.item(i),
                                                      "DomainManager" );

                if( v_hostname.elementAt( 0 ).equals( hostname ) &&
                    v_https_admin_port.elementAt( 0 ).equals( Integer.toString(httpsadminport) ) ) {
                    dm = v_domain_mgr.elementAt( 0 ).toString();
                    break;
                }
            }
        } catch (Exception e) {
            CMS.debug( e.toString() );
        }
        return dm.equalsIgnoreCase("true");
    }
 
    public Vector getMasterUrlListFromSecurityDomain( IConfigStore config,
                                                      String type,
                                                      String portType ) {
        Vector v = new Vector();

        try {
            String hostname = config.getString("securitydomain.host");
            int httpsadminport = config.getInteger("securitydomain.httpsadminport");

            CMS.debug("Getting domain.xml from CA...");
            String c = getDomainXML(hostname, httpsadminport, true);
            String list = "";

            CMS.debug("Type " + type);
            if (type.equals("CA")) {
                list = "CAList";
            } else if (type.equals("KRA")) {
                list = "KRAList";
            } else if (type.equals("OCSP")) {
                list = "OCSPList";
            } else if (type.equals("TKS")) {
                list = "TKSList";
            }

            CMS.debug( "Getting " + portType + " from Security Domain ..." );
            if( !portType.equals( "UnSecurePort" )    &&
                !portType.equals( "SecureAgentPort" ) &&
                !portType.equals( "SecurePort" )      &&
                !portType.equals( "SecureAdminPort" ) ) {
                CMS.debug( "getPortFromSecurityDomain:  " +
                           "unknown port type " + portType );
                return v;
            }

            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject parser = new XMLObject(bis);
            Document doc = parser.getDocument();
            NodeList nodeList = doc.getElementsByTagName(type);

            // save domain name in cfg
            config.putString("securitydomain.name",
                    parser.getValue("Name"));

            int len = nodeList.getLength();

            CMS.debug("Len " + len);
            for (int i = 0; i < len; i++) {
                Vector v_clone = parser.getValuesFromContainer(nodeList.item(i),
                  "Clone");
                String clone = (String)v_clone.elementAt(0);
                if (clone.equalsIgnoreCase("true"))
                    continue;
                Vector v_name = parser.getValuesFromContainer(nodeList.item(i),
                        "SubsystemName");
                Vector v_host = parser.getValuesFromContainer(nodeList.item(i),
                        "Host");
                Vector v_port = parser.getValuesFromContainer(nodeList.item(i),
                        portType);

                v.addElement( v_name.elementAt(0)
                            + " - https://"
                            + v_host.elementAt(0)
                            + ":"
                            + v_port.elementAt(0) );
            }
        } catch (Exception e) {
            CMS.debug(e.toString());
        }

        return v;
    }

    public Vector getUrlListFromSecurityDomain( IConfigStore config,
                                                String type,
                                                String portType ) {
        Vector v = new Vector();

        try {
            String hostname = config.getString("securitydomain.host");
            int httpsadminport = config.getInteger("securitydomain.httpsadminport");

            CMS.debug("Getting domain.xml from CA...");
            String c = getDomainXML(hostname, httpsadminport, true);
            String list = "";

            CMS.debug("Subsystem Type " + type);
            if (type.equals("CA")) {
                list = "CAList";
            } else if (type.equals("KRA")) {
                list = "KRAList";
            } else if (type.equals("OCSP")) {
                list = "OCSPList";
            } else if (type.equals("TKS")) {
                list = "TKSList";
            }

            CMS.debug( "Getting " + portType + " from Security Domain ..." );
            if( !portType.equals( "UnSecurePort" )    &&
                !portType.equals( "SecureAgentPort" ) &&
                !portType.equals( "SecurePort" )      &&
                !portType.equals( "SecureAdminPort" ) ) {
                CMS.debug( "getPortFromSecurityDomain:  " +
                           "unknown port type " + portType );
                return v;
            }

            ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
            XMLObject parser = new XMLObject(bis);
            Document doc = parser.getDocument();
            NodeList nodeList = doc.getElementsByTagName(type);

            // save domain name in cfg
            config.putString("securitydomain.name",
                    parser.getValue("Name"));

            int len = nodeList.getLength();

            CMS.debug("Len " + len);
            for (int i = 0; i < len; i++) {
                Vector v_name = parser.getValuesFromContainer(nodeList.item(i),
                        "SubsystemName");
                Vector v_host = parser.getValuesFromContainer(nodeList.item(i),
                        "Host");
                Vector v_port = parser.getValuesFromContainer(nodeList.item(i),
                        portType);
                Vector v_admin_port = parser.getValuesFromContainer(nodeList.item(i),
                        "SecureAdminPort");

                if (v_host.elementAt(0).equals(hostname) && v_admin_port.elementAt(0).equals(new Integer(httpsadminport).toString())) {
                    // add security domain CA to the beginning of list
                    v.add( 0, v_name.elementAt(0)
                            + " - https://"
                            + v_host.elementAt(0)
                            + ":"
                            + v_port.elementAt(0) );
                } else {
                    v.addElement( v_name.elementAt(0)
                            + " - https://"
                            + v_host.elementAt(0)
                            + ":"
                            + v_port.elementAt(0) );
                }
            }
        } catch (Exception e) {
            CMS.debug(e.toString());
        }

        return v;
    }

    // Given an HTTPS Hostname and EE port,
    // retrieve the associated HTTPS Admin port
    public String getSecurityDomainAdminPort( IConfigStore config,
                                              String hostname,
                                              String https_ee_port,
                                              String cstype ) {
        String https_admin_port = new String();

        try {
            String sd_hostname = config.getString( "securitydomain.host" );
            int sd_httpsadminport =
                config.getInteger( "securitydomain.httpsadminport" );

            CMS.debug( "Getting domain.xml from CA ..." );
            String c = getDomainXML( sd_hostname, sd_httpsadminport, true );

            CMS.debug( "Getting associated HTTPS Admin port from " +
                       "HTTPS Hostname '" + hostname +
                       "' and EE port '" + https_ee_port + "'" );
            ByteArrayInputStream bis = new ByteArrayInputStream( c.getBytes() );
            XMLObject parser = new XMLObject( bis );
            Document doc = parser.getDocument();
            NodeList nodeList = doc.getElementsByTagName( cstype.toUpperCase() );

            int len = nodeList.getLength();
            for( int i = 0; i < len; i++ ) {
                Vector v_hostname =
                       parser.getValuesFromContainer( nodeList.item(i),
                                                      "Host" );

                Vector v_https_ee_port =
                       parser.getValuesFromContainer( nodeList.item(i),
                                                      "SecurePort" );

                Vector v_https_admin_port =
                       parser.getValuesFromContainer( nodeList.item(i),
                                                      "SecureAdminPort" );

                if( v_hostname.elementAt( 0 ).equals( hostname ) &&
                    v_https_ee_port.elementAt( 0 ).equals( https_ee_port ) ) {
                    https_admin_port =
                                v_https_admin_port.elementAt( 0 ).toString();
                    break;
                }
            }
        } catch (Exception e) {
            CMS.debug( e.toString() );
        }

        return( https_admin_port );
    }

    public String getSecurityDomainPort( IConfigStore config,
                                         String portType ) {
        String port = new String();

        try {
            String hostname = config.getString( "securitydomain.host" );
            int httpsadminport =
                config.getInteger( "securitydomain.httpsadminport" );

            CMS.debug( "Getting domain.xml from CA ..." );
            String c = getDomainXML( hostname, httpsadminport, true );

            CMS.debug( "Getting " + portType + " from Security Domain ..." );
            if( !portType.equals( "UnSecurePort" )    &&
                !portType.equals( "SecureAgentPort" ) &&
                !portType.equals( "SecurePort" )      &&
                !portType.equals( "SecureAdminPort" ) ) {
                CMS.debug( "getPortFromSecurityDomain:  " +
                           "unknown port type " + portType );
                return "";
            }

            ByteArrayInputStream bis = new ByteArrayInputStream( c.getBytes() );
            XMLObject parser = new XMLObject( bis );
            Document doc = parser.getDocument();
            NodeList nodeList = doc.getElementsByTagName( "CA" );

            int len = nodeList.getLength();
            for( int i = 0; i < len; i++ ) {
                Vector v_admin_port =
                       parser.getValuesFromContainer( nodeList.item(i),
                                                      "SecureAdminPort" );

                Vector v_port = null;
                if( portType.equals( "UnSecurePort" ) ) {
                    v_port = parser.getValuesFromContainer( nodeList.item(i),
                                                            "UnSecurePort" );
                } else if( portType.equals( "SecureAgentPort" ) ) {
                    v_port = parser.getValuesFromContainer( nodeList.item(i),
                                                            "SecureAgentPort" );
                } else if( portType.equals( "SecurePort" ) ) {
                    v_port = parser.getValuesFromContainer( nodeList.item(i),
                                                            "SecurePort" );
                } else if( portType.equals( "SecureAdminPort" ) ) {
                    v_port = parser.getValuesFromContainer( nodeList.item(i),
                                                            "SecureAdminPort" );
                }

                if( ( v_port != null ) &&
                    ( v_admin_port.elementAt( 0 ).equals(
                      Integer.toString( httpsadminport ) ) ) ) {
                    port = v_port.elementAt( 0 ).toString();
                    break;
                }
            }
        } catch (Exception e) {
            CMS.debug( e.toString() );
        }

        return( port );
    }

    public String pingCS( String hostname, int port, boolean https,
                          SSLCertificateApprovalCallback certApprovalCallback )
        throws IOException {
        CMS.debug( "WizardPanelBase pingCS: started" );

        String c = getHttpResponse( hostname, port, https,
                                    "/ca/admin/ca/getStatus", 
                                    null, null, certApprovalCallback );

        if( c != null ) {
            try {
                ByteArrayInputStream bis = new
                                           ByteArrayInputStream( c.getBytes() );
                XMLObject parser = null;
                String state = null;

                try {
                    parser = new XMLObject( bis );
                    CMS.debug( "WizardPanelBase pingCS: got XML parsed" );
                    state = parser.getValue( "State" );

                    if( state != null ) {
                        CMS.debug( "WizardPanelBase pingCS: state=" + state );
                    }
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase: pingCS: parser failed"
                             + e.toString() );
                }

                return state;
            } catch( Exception e ) {
                CMS.debug( "WizardPanelBase: pingCS: " + e.toString() );
                throw new IOException( e.toString() );
            }
        }

        CMS.debug( "WizardPanelBase pingCS: stopped" );
        return null;
    }

    public String toLowerCaseSubsystemType(String s) {
        String x = null;
        if (s.equals("CA")) {
            x = "ca";
        } else if (s.equals("KRA")) {
            x = "kra"; 
        } else if (s.equals("OCSP")) {
            x = "ocsp";
        } else if (s.equals("TKS")) {
            x = "tks";
        }

        return x;
    }

    public void getTokenInfo(IConfigStore config, String type, String host, 
      int https_ee_port, boolean https, Context context, 
      ConfigCertApprovalCallback certApprovalCallback) throws IOException {
        CMS.debug("WizardPanelBase getTokenInfo start");
        String uri = "/"+type+"/ee/"+type+"/getTokenInfo";
        CMS.debug("WizardPanelBase getTokenInfo: uri="+uri);
        String c = getHttpResponse(host, https_ee_port, https, uri, null, null,
          certApprovalCallback);
        if (c != null) {
            try {
                ByteArrayInputStream bis = new ByteArrayInputStream(c.getBytes());
                XMLObject parser = null;

                try {
                    parser = new XMLObject(bis);
                } catch (Exception e) {
                    CMS.debug( "WizardPanelBase::getTokenInfo() - "
                             + "Exception="+e.toString() );
                    throw new IOException( e.toString() );
                }

                String status = parser.getValue("Status");

                CMS.debug("WizardPanelBase getTokenInfo: status=" + status);

                if (status.equals(SUCCESS)) {
                    Document doc = parser.getDocument();
                    NodeList list = doc.getElementsByTagName("name");
                    int len = list.getLength();
                    for (int i=0; i<len; i++) {
                        Node n = list.item(i);
                        NodeList nn = n.getChildNodes();
                        String name = nn.item(0).getNodeValue();
                        Node parent = n.getParentNode();
                        nn = parent.getChildNodes();
                        int len1 = nn.getLength();
                        String v = "";
                        for (int j=0; j<len1; j++) {
                            Node nv = nn.item(j);
                            String val = nv.getNodeName();
                            if (val.equals("value")) {
                                NodeList n2 = nv.getChildNodes();
                                if (n2.getLength() > 0)
                                    v = n2.item(0).getNodeValue();
                                break;    
                            }
                        }
                        if (name.equals("cloning.signing.nickname")) {                            
                            config.putString("preop.master.signing.nickname", v);
                            config.putString(type + ".cert.signing.nickname", v);
                            config.putString(name, v);
                        } else if (name.equals("cloning.ocsp_signing.nickname")) {
                            config.putString("preop.master.ocsp_signing.nickname", v);
                            config.putString(type + ".cert.ocsp_signing.nickname", v);
                            config.putString(name, v);
                        } else if (name.equals("cloning.subsystem.nickname")) {
                            config.putString("preop.master.subsystem.nickname", v);
                            config.putString(type + ".cert.subsystem.nickname", v);
                            config.putString(name, v);
                        } else if (name.equals("cloning.transport.nickname")) {
                            config.putString("preop.master.transport.nickname", v);
                            config.putString("kra.transportUnit.nickName", v);
                            config.putString("kra.cert.transport.nickname", v);
                            config.putString(name, v);
                        } else if (name.equals("cloning.storage.nickname")) {
                            config.putString("preop.master.storage.nickname", v);
                            config.putString("kra.storageUnit.nickName", v);
                            config.putString("kra.cert.storage.nickname", v);
                            config.putString(name, v);
                        } else if (name.equals("cloning.audit_signing.nickname")) {
                            config.putString("preop.master.audit_signing.nickname", v);
                            config.putString(type + ".cert.audit_signing.nickname", v);
                            config.putString(name, v);
                        } else if (name.equals("cloning.module.token")) {
                            config.putString("preop.module.token", v);
                        } else if (name.startsWith("cloning.ca")) {
                            config.putString(name.replaceFirst("cloning", "preop"), v);
                        } else if (name.startsWith("cloning")) {
                            config.putString(name.replaceFirst("cloning", "preop.cert"), v);
                        } else {
                            config.putString(name, v);
                        }
                    }

                    // reset nicknames for system cert verification
                    String token = config.getString("preop.module.token", 
                                                    "Internal Key Storage Token");
                    if (! token.equals("Internal Key Storage Token")) {
                        String certlist = config.getString("preop.cert.list");

                        StringTokenizer t1 = new StringTokenizer(certlist, ",");
                        while (t1.hasMoreTokens()) {
                            String tag = t1.nextToken();
                            if (tag.equals("sslserver")) continue;
                            config.putString(type + ".cert." + tag + ".nickname", 
                                token + ":" + 
                                config.getString(type + ".cert." + tag + ".nickname", ""));
                        } 
                    }
                } else {
                    String error = parser.getValue("Error");
                    throw new IOException(error);
                }
            } catch (IOException e) {
                CMS.debug("WizardPanelBase: getTokenInfo: " + e.toString());
                throw e;
            } catch (Exception e) {
                CMS.debug("WizardPanelBase: getTokenInfo: " + e.toString());
                throw new IOException(e.toString());
            }
        }           
    }

    public void importCertChain(String id) throws IOException {
        CMS.debug("DisplayCertChainPanel importCertChain");
        IConfigStore config = CMS.getConfigStore();
        String configName = "preop." + id + ".pkcs7";
        String pkcs7 = "";

        try {
            pkcs7 = config.getString(configName, "");
        } catch (Exception e) {}

        if (pkcs7.length() > 0) {
            try {
                CryptoUtil.importCertificateChain(pkcs7);
            } catch (Exception e) {
                CMS.debug("DisplayCertChainPanel importCertChain: Exception: "+e.toString());
            }
        }
    }

    public void updateCertChain(IConfigStore config, String name, String host,
      int https_admin_port, boolean https, Context context) throws IOException {
        updateCertChain( config, name, host, https_admin_port,
                         https, context, null );
    }

    public void updateCertChain(IConfigStore config, String name, String host,
      int https_admin_port, boolean https, Context context, 
      ConfigCertApprovalCallback certApprovalCallback) throws IOException {
        String certchain = getCertChainUsingSecureAdminPort( host,
                                                             https_admin_port,
                                                             https,
                                                             certApprovalCallback );
        config.putString("preop."+name+".pkcs7", certchain);

        byte[] decoded = CryptoUtil.base64Decode(certchain);
        java.security.cert.X509Certificate[] b_certchain = null;

        try {
            b_certchain = CryptoUtil.getX509CertificateFromPKCS7(decoded);
        } catch (Exception e) {
            context.put("errorString",
              "Failed to get the certificate chain.");
            return;
        }

        int size = 0;
        if (b_certchain != null) {
            size = b_certchain.length;
        }
        config.putInteger("preop."+name+".certchain.size", size);
        for (int i = 0; i < size; i++) {
            byte[] bb = null;

            try {
                bb = b_certchain[i].getEncoded();
            } catch (Exception e) {
                context.put("errorString",
                  "Failed to get the der-encoded certificate chain.");
                return;
            }
            config.putString("preop."+name+".certchain." + i,
              CryptoUtil.normalizeCertStr(CryptoUtil.base64Encode(bb)));
        }

        try {
            config.commit(false);
        } catch (EBaseException e) {
        }
    }

    public void updateCertChainUsingSecureEEPort( IConfigStore config,
                                                  String name, String host,
                                                  int https_ee_port,
                                                  boolean https,
                                                  Context context, 
                                                  ConfigCertApprovalCallback certApprovalCallback ) throws IOException {
        String certchain = getCertChainUsingSecureEEPort( host, https_ee_port,
                                                          https,
                                                          certApprovalCallback);
        config.putString("preop."+name+".pkcs7", certchain);

        byte[] decoded = CryptoUtil.base64Decode(certchain);
        java.security.cert.X509Certificate[] b_certchain = null;

        try {
            b_certchain = CryptoUtil.getX509CertificateFromPKCS7(decoded);
        } catch (Exception e) {
            context.put("errorString",
              "Failed to get the certificate chain.");
            return;
        }

        int size = 0;
        if (b_certchain != null) {
            size = b_certchain.length;
        }
        config.putInteger("preop."+name+".certchain.size", size);
        for (int i = 0; i < size; i++) {
            byte[] bb = null;

            try {
                bb = b_certchain[i].getEncoded();
            } catch (Exception e) {
                context.put("errorString",
                  "Failed to get the der-encoded certificate chain.");
                return;
            }
            config.putString("preop."+name+".certchain." + i,
              CryptoUtil.normalizeCertStr(CryptoUtil.base64Encode(bb)));
        }

        try {
            config.commit(false);
        } catch (EBaseException e) {
        }
    }

    public void deleteCert(String tokenname, String nickname) {
        try {
            CryptoManager cm = CryptoManager.getInstance();
            CryptoToken tok = cm.getTokenByName(tokenname);
            CryptoStore store = tok.getCryptoStore();
            String fullnickname = nickname;
            if (!tokenname.equals("") &&
                !tokenname.equals("Internal Key Storage Token") &&
                !tokenname.equals("internal"))
                  fullnickname = tokenname+":"+nickname;

            CMS.debug("WizardPanelBase deleteCert: nickname="+fullnickname);
            org.mozilla.jss.crypto.X509Certificate cert = cm.findCertByNickname(fullnickname);

            if (store instanceof PK11Store) {
                CMS.debug("WizardPanelBase deleteCert: this is pk11store");
                PK11Store pk11store = (PK11Store)store;
                pk11store.deleteCertOnly(cert);
                CMS.debug("WizardPanelBase deleteCert: cert deleted successfully");
            }
        } catch (Exception e) {
            CMS.debug("WizardPanelBase deleteCert: Exception="+e.toString());
        }
    }

    public void deleteEntries(LDAPSearchResults res, LDAPConnection conn,
      String dn, String[] entries) {
        String[] attrs = null;
        LDAPSearchConstraints cons = null;
        String filter = "objectclass=*";

        try {
            if (res.getCount() == 0)
                return;
            else {
                while (res.hasMoreElements()) {
                    LDAPEntry entry = res.next();
                    String dn1 = entry.getDN();
                    LDAPSearchResults res1 = conn.search(dn1, 1, filter, attrs, true, cons);
                    deleteEntries(res1, conn, dn1, entries);
                    deleteEntry(conn, dn1, entries);
                }
            }
        } catch (Exception ee) {
            CMS.debug("WizardPanelBase deleteEntries: Exception="+ee.toString());
        }
    }

    public void deleteEntry(LDAPConnection conn, String dn, String[] entries) {
        try {
            for (int i=0; i<entries.length; i++) {
                if (LDAPDN.equals(dn, entries[i])) {
                    CMS.debug("WizardPanelBase deleteEntry: entry with this dn "+dn+" is not deleted.");
                    return;
                }
            }

            CMS.debug("WizardPanelBase deleteEntry: deleting dn="+dn);
            conn.delete(dn);
        } catch (Exception e) {
            CMS.debug("WizardPanelBase deleteEntry: Exception="+e.toString());
        }
    }

    public void reloginSecurityDomain(HttpServletResponse response) {
        IConfigStore cs = CMS.getConfigStore();
        try {
            String hostname = cs.getString("securitydomain.host", "");
            int port = cs.getInteger("securitydomain.httpsadminport", -1);
            String cs_hostname = cs.getString("machineName", "");
            int cs_port = cs.getInteger("pkicreate.admin_secure_port", -1);
            int panel = getPanelNo();
            String subsystem = cs.getString("cs.type", "");
            String urlVal = "https://"+cs_hostname+":"+cs_port+"/"+toLowerCaseSubsystemType(subsystem)+"/admin/console/config/wizard?p="+panel+"&subsystem="+subsystem;
            String encodedValue = URLEncoder.encode(urlVal, "UTF-8");
            String sdurl =  "https://"+hostname+":"+port+"/ca/admin/ca/securityDomainLogin?url="+encodedValue;
            response.sendRedirect(sdurl);
        } catch (Exception e) {
            CMS.debug("WizardPanelBase reloginSecurityDomain: Exception="+e.toString());
        }
    }
}
