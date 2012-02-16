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
import com.netscape.cmsutil.xml.*;
import com.netscape.certsrv.base.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.usrgrp.*;
import com.netscape.certsrv.property.*;
import com.netscape.certsrv.authority.*;
import com.netscape.certsrv.dbs.crldb.*;
import com.netscape.certsrv.ocsp.*;
import com.netscape.certsrv.logging.*;
import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.*;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.password.*;
import netscape.security.x509.*;
import netscape.ldap.*;
import java.net.*;
import java.io.*;
import java.math.*;
import java.security.cert.*;

import org.mozilla.jss.CryptoManager;
import org.w3c.dom.*;
import java.util.*;

import com.netscape.cms.servlet.wizard.*;

public class DonePanel extends WizardPanelBase {

    public static final BigInteger BIG_ZERO = new BigInteger("0");
    public static final Long MINUS_ONE = Long.valueOf(-1);
    public static final String RESTART_SERVER_AFTER_CONFIGURATION =
        "restart_server_after_configuration";
    public static final String PKI_SECURITY_DOMAIN = "pki_security_domain";

    public DonePanel() {}

    /**
     * Initializes this panel.
     */
    public void init(ServletConfig config, int panelno) 
        throws ServletException {
        setPanelNo(panelno);
        setName("Done");
    }

    public void init(WizardServlet servlet, ServletConfig config, int panelno, String id)
        throws ServletException {
        setPanelNo(panelno);
        setName("Done");
        setId(id);
    }

    public boolean hasSubPanel() {
        return false;
    }

    public void cleanUp() throws IOException {
    }

    public PropertySet getUsage() {
        PropertySet set = new PropertySet();
                                                                                
        /* XXX */
                                                                                
        return set;
    }

    private LDAPConnection getLDAPConn(Context context)
            throws IOException
    {
        IConfigStore cs = CMS.getConfigStore();

        String host = "";
        String port = "";
        String pwd = null;
        String binddn = "";
        String security = "";

        IPasswordStore pwdStore = CMS.getPasswordStore();

        if (pwdStore != null) {
            CMS.debug("DonePanel: getLDAPConn: password store available");
            pwd = pwdStore.getPassword("internaldb");
        }

        if ( pwd == null) {
           throw new IOException("DonePanel: Failed to obtain password from password store");
        }

        try {
            host = cs.getString("internaldb.ldapconn.host");
            port = cs.getString("internaldb.ldapconn.port");
            binddn = cs.getString("internaldb.ldapauth.bindDN");
            security = cs.getString("internaldb.ldapconn.secureConn");
        } catch (Exception e) {
            CMS.debug("DonePanel: getLDAPConn" + e.toString());
            throw new IOException(
                    "Failed to retrieve LDAP information from CS.cfg.");
        }

        int p = -1;

        try {
            p = Integer.parseInt(port);
        } catch (Exception e) {
            CMS.debug("DonePanel getLDAPConn: " + e.toString());
            throw new IOException("Port is not valid");
        }

        LDAPConnection conn = null;
        if (security.equals("true")) {
          CMS.debug("DonePanel getLDAPConn: creating secure (SSL) connection for internal ldap");
          conn = new LDAPConnection(CMS.getLdapJssSSLSocketFactory());
        } else {
          CMS.debug("DonePanel getLDAPConn: creating non-secure (non-SSL) connection for internal ldap");
          conn = new LDAPConnection();
        }

        CMS.debug("DonePanel connecting to " + host + ":" + p);
        try {
            conn.connect(host, p, binddn, pwd);
        } catch (LDAPException e) {
            CMS.debug("DonePanel getLDAPConn: " + e.toString());
            throw new IOException("Failed to connect to the internal database.");
        }

      return conn;
    }


    /**
     * Display the panel.
     */
    public void display(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {
        CMS.debug("DonePanel: display()");

        // update session id 
        String session_id = request.getParameter("session_id");
        if (session_id != null) {
            CMS.debug("NamePanel setting session id.");
            CMS.setConfigSDSessionId(session_id);
        }

        IConfigStore cs = CMS.getConfigStore();
        String ownport = CMS.getEENonSSLPort();
        String ownsport = CMS.getEESSLPort();
        String owneeclientauthsport = CMS.getEEClientAuthSSLPort();
        String ownhost = CMS.getEESSLHost();
        String ownagentsport = CMS.getAgentPort();
        String ownagenthost = CMS.getAgentHost();
        String ownadminsport = CMS.getAdminPort();
        String ownadminhost = CMS.getAdminHost();
        String select = "";

        String type = "";
        String instanceId = "";
        String instanceRoot = "";
        String systemdService = "";
        try {
            type = cs.getString("cs.type", "");
            instanceId = cs.getString("instanceId");
            instanceRoot = cs.getString("instanceRoot");
            select = cs.getString("preop.subsystem.select", "");
            systemdService = cs.getString("pkicreate.systemd.servicename", "");
        } catch (Exception e) {}

        String initDaemon = "";
        if (type.equals("CA")) {
			initDaemon = "pki-cad";
        } else if (type.equals("KRA")) {
			initDaemon = "pki-krad";
        } else if (type.equals("OCSP")) {
			initDaemon = "pki-ocspd";
        } else if (type.equals("TKS")) {
			initDaemon = "pki-tksd";
        }
        String os = System.getProperty( "os.name" );
        if( os.equalsIgnoreCase( "Linux" ) ) {
            if (! systemdService.equals("")) {
                context.put( "initCommand", "/bin/systemctl");
                context.put( "instanceId", systemdService );
            } else {
                context.put( "initCommand", "/sbin/service " + initDaemon );
                context.put( "instanceId", instanceId );
            }
        } else {
            /* default case:  e. g. - ( os.equalsIgnoreCase( "SunOS" ) */
            context.put( "initCommand", "/etc/init.d/" + initDaemon );
            context.put( "instanceId", instanceId );
        }
        context.put("title", "Done");
        context.put("panel", "admin/console/config/donepanel.vm");
        context.put("host", ownadminhost);
        context.put("port", ownadminsport);
        String subsystemType = toLowerCaseSubsystemType(type);
        context.put("systemType", subsystemType);

        try {
            int state = cs.getInteger("cs.state");
            if (state == 1) {
                context.put("csstate", "1");
                return;
            } else
                context.put("csstate", "0");
       
        } catch (Exception e) {
        }

        String sd_agent_port = "";
        String sd_admin_port = "";
        String sd_host = "";
        String ca_host = "";
        try {
            sd_host = cs.getString("securitydomain.host", "");
            sd_agent_port = cs.getString("securitydomain.httpsagentport", "");
            sd_admin_port = cs.getString("securitydomain.httpsadminport", "");
            ca_host = cs.getString("preop.ca.hostname", "");
        } catch (Exception e) {
        }

        if (ca_host.equals(""))
            context.put("externalCA", "true");
        else
            context.put("externalCA", "false");

        // update security domain
        String sdtype = "";
        String instanceName = "";
        String subsystemName = "";
        try {
            sdtype = cs.getString("securitydomain.select", "");
            instanceName = cs.getString("instanceId", "");
            subsystemName = cs.getString("preop.subsystem.name", "");
        } catch (Exception e) {
        }

        boolean cloneMaster = false;

        if (select.equals("clone") && type.equalsIgnoreCase("CA") && isSDHostDomainMaster(cs)) {
            cloneMaster = true;
            CMS.debug("Cloning a domain master");
        }

        String s = getSubsystemNodeName(type);
        if (sdtype.equals("new")) {
            try {
                LDAPConnection conn = getLDAPConn(context);

                String basedn = cs.getString("internaldb.basedn");
                String secdomain = cs.getString("securitydomain.name");

                try {                
                    // Create security domain ldap entry
                    String dn = "ou=Security Domain," + basedn;
                    CMS.debug("DonePanel: creating ldap entry : " + dn);
                 
                    LDAPEntry entry = null;
                    LDAPAttributeSet attrs = null;
                    attrs = new LDAPAttributeSet();
                    attrs.add(new LDAPAttribute("objectclass", "top"));
                    attrs.add(new LDAPAttribute("objectclass", "pkiSecurityDomain"));
                    if (secdomain.equals("")) {
                        // this should not happen - just in case
                        CMS.debug("DonePanel display(): Security domain is an empty string!");
                        throw new IOException("Security domain is an empty string!");
                    } else {
                        attrs.add(new LDAPAttribute("name", secdomain));
                    }
                    attrs.add(new LDAPAttribute("ou", "Security Domain"));
                    entry = new LDAPEntry(dn, attrs);
                    conn.add(entry);
                } catch (Exception e) {
                    CMS.debug("Unable to create security domain");
                    throw e;
                }

                try { 
                    // create list containers
                    String clist[] = {"CAList", "OCSPList", "KRAList", "RAList", "TKSList", "TPSList"};
                    for (int i=0; i< clist.length; i++) {
                        LDAPEntry entry = null;
                        LDAPAttributeSet attrs = null;
                        String dn = "cn=" + clist[i] + ",ou=Security Domain," + basedn;
                        attrs = new LDAPAttributeSet();
                        attrs.add(new LDAPAttribute("objectclass", "top"));
                        attrs.add(new LDAPAttribute("objectclass", "pkiSecurityGroup"));
                        attrs.add(new LDAPAttribute("cn", clist[i]));
                        entry = new LDAPEntry(dn, attrs);
                        conn.add(entry);
                    }
                } catch (Exception e) {
                    CMS.debug("Unable to create security domain list groups" );
                    throw e;
                }  

                try {
                    // Add this host (only CA can create new domain) 
                    String cn = ownhost + ":" + ownadminsport;
                    String dn = "cn=" + cn + ",cn=CAList,ou=Security Domain," + basedn;
                    LDAPEntry entry = null;
                    LDAPAttributeSet attrs = null;
                    attrs = new LDAPAttributeSet();
                    attrs.add(new LDAPAttribute("objectclass", "top"));
                    attrs.add(new LDAPAttribute("objectclass", "pkiSubsystem"));
                    attrs.add(new LDAPAttribute("Host", ownhost));
                    attrs.add(new LDAPAttribute("SecurePort", ownsport));
                    attrs.add(new LDAPAttribute("SecureAgentPort",
                              ownagentsport));
                    attrs.add(new LDAPAttribute("SecureAdminPort",
                              ownadminsport));
                    if (owneeclientauthsport != null) {
                        attrs.add(new LDAPAttribute("SecureEEClientAuthPort", 
                              owneeclientauthsport));
                    }
                    attrs.add(new LDAPAttribute("UnSecurePort", ownport));
                    attrs.add(new LDAPAttribute("Clone", "FALSE"));
                    attrs.add(new LDAPAttribute("SubsystemName", subsystemName));
                    attrs.add(new LDAPAttribute("cn", cn));
                    attrs.add(new LDAPAttribute("DomainManager", "TRUE"));
                    entry = new LDAPEntry(dn, attrs);
                    conn.add(entry);
                } catch (Exception e) {
                    CMS.debug("Unable to create host entry in security domain");
                    throw e;
                }
                CMS.debug("DonePanel display: finish updating domain info");
                conn.disconnect();
            } catch (Exception e) {
                CMS.debug("DonePanel display: "+e.toString());
            }

            int sd_admin_port_int = -1;
            try {
                sd_admin_port_int = Integer.parseInt( sd_admin_port );
            } catch (Exception e) {
            }

            try {
                // Fetch the "new" security domain and display it
                CMS.debug( "Dump contents of new Security Domain . . ." );
                String c = getDomainXML( sd_host, sd_admin_port_int, true );
            } catch( Exception e ) {}

            // Since this instance is a new Security Domain,
            // create an empty file to designate this fact.
            String security_domain = instanceRoot + "/conf/"
                                   + PKI_SECURITY_DOMAIN;
            if( !Utils.isNT() ) {
                Utils.exec( "touch " + security_domain );
                Utils.exec( "chmod 00660 " + security_domain );
            }

        } else { //existing domain
            int sd_agent_port_int = -1;
            int sd_admin_port_int = -1;
            try {
                sd_agent_port_int = Integer.parseInt(sd_agent_port);
                sd_admin_port_int = Integer.parseInt(sd_admin_port);
            } catch (Exception e) {
            }

            try {
                String cloneStr = "";
                if (select.equals("clone"))
                    cloneStr = "&clone=true";
                else
                    cloneStr = "&clone=false";

                String domainMasterStr = "";
                if (cloneMaster) 
                    domainMasterStr = "&dm=true";
                else 
                    domainMasterStr = "&dm=false"; 
                String eecaStr = "";
                if (owneeclientauthsport != null) 
                    eecaStr="&eeclientauthsport=" + owneeclientauthsport;

                updateDomainXML( sd_host, sd_agent_port_int, true,
                                 "/ca/agent/ca/updateDomainXML", 
                                 "list=" + s
                               + "&type=" + type
                               + "&host=" + ownhost
                               + "&name=" + subsystemName
                               + "&sport=" + ownsport
                               + domainMasterStr 
                               + cloneStr
                               + "&agentsport=" + ownagentsport
                               + "&adminsport=" + ownadminsport
                               + eecaStr 
                               + "&httpport=" + ownport );

                // Fetch the "updated" security domain and display it
                CMS.debug( "Dump contents of updated Security Domain . . ." );
                String c = getDomainXML( sd_host, sd_admin_port_int, true );
            } catch (Exception e) {
                context.put("errorString", "Failed to update the security domain on the domain master.");
                //return;
            }
        }

        // add service.securityDomainPort to CS.cfg in case pkiremove
        // needs to remove system reference from the security domain
        try {
            cs.putString("service.securityDomainPort", ownagentsport);
            cs.putString("securitydomain.store", "ldap");
            cs.commit(false);
        } catch (Exception e) {
            CMS.debug("DonePanel: exception in adding service.securityDomainPort to CS.cfg" + e);
        }


        // need to push connector information to the CA
        if (type.equals("KRA") && !ca_host.equals("")) {
            try {
                updateConnectorInfo(ownagenthost, ownagentsport);
            } catch (IOException e) {
                context.put("errorString", "Failed to update connector information.");
                return;
            }
            setupClientAuthUser();
        } // if KRA

        // import the CA certificate into the OCSP
        // configure the CRL Publishing to OCSP in CA
        if (type.equals("OCSP") && !ca_host.equals("")) {
            try {
                CMS.reinit(IOCSPAuthority.ID);
                importCACertToOCSP();
            } catch (Exception e) {
                CMS.debug("DonePanel display: Failed to import the CA certificate into OCSP.");
            }

            try {
                updateOCSPConfig(response);
            } catch (Exception e) {
                CMS.debug("DonePanel display: Failed to update OCSP information in CA.");
            }

            setupClientAuthUser();
        }
        
        if (!select.equals("clone")) {
            if (type.equals("CA") || type.equals("KRA")) {
                String beginRequestNumStr = "";
                String endRequestNumStr = "";
                String beginSerialNumStr = "";
                String endSerialNumStr = "";
                String requestIncStr = "";
                String serialIncStr = "";
              
                try {
                    endRequestNumStr = cs.getString("dbs.endRequestNumber", "");
                    endSerialNumStr = cs.getString("dbs.endSerialNumber", "");
                    BigInteger endRequestNum = new BigInteger(endRequestNumStr);
                    BigInteger endSerialNum = new BigInteger(endSerialNumStr);
                    BigInteger oneNum = new BigInteger("1");

                    // update global next range entries
                    LDAPConnection conn = getLDAPConn(context);
                    String basedn = cs.getString("internaldb.basedn");

                    String serialdn = "";
                    if (type.equals("CA")) {
                        serialdn = "ou=certificateRepository,ou=" + type.toLowerCase() + "," + basedn;
                    } else {
                        serialdn = "ou=keyRepository,ou=" + type.toLowerCase() + "," + basedn;
                    } 
                    LDAPAttribute attrSerialNextRange = new LDAPAttribute( "nextRange", endSerialNum.add(oneNum).toString());
                    LDAPModification serialmod = new LDAPModification( LDAPModification.REPLACE, attrSerialNextRange );
                    conn.modify( serialdn, serialmod );

                    String requestdn = "ou=" + type.toLowerCase() + ",ou=requests," + basedn;
                    LDAPAttribute attrRequestNextRange = new LDAPAttribute( "nextRange", endRequestNum.add(oneNum).toString());
                    LDAPModification requestmod = new LDAPModification( LDAPModification.REPLACE, attrRequestNextRange );
                    conn.modify( requestdn, requestmod );      

                    conn.disconnect();            
                } catch (Exception e) {
                    CMS.debug("Unable to update global next range numbers: " + e);
                } 
            }
        } 

        if (cloneMaster) {
            // cloning a domain master CA, the clone is also master of its domain
            try {
                cs.putString("securitydomain.host", ownhost);
                cs.putString("securitydomain.httpport", ownport);
                cs.putString("securitydomain.httpsadminport", ownadminsport);
                cs.putString("securitydomain.httpsagentport", ownagentsport);
                cs.putString("securitydomain.httpseeport", ownsport);
                cs.putString("securitydomain.select", "new");
            } catch (Exception e) {
                CMS.debug("Caught exception trying to save security domain parameters for clone of a domain master");
            }
        }

        String dbuser = null;
        try {
            dbuser = cs.getString("cs.type") + "-" + cs.getString("machineName") + "-" + cs.getString("service.securePort");
            if (! sdtype.equals("new")) {
                setupDBUser(dbuser);
            }
            IUGSubsystem system = (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));
            IUser user = system.getUser(dbuser);
            system.addCertSubjectDN(user);
        } catch (Exception e) {
            e.printStackTrace();
            CMS.debug("Unable to create or update dbuser" + e);
        }

        cs.putInteger("cs.state", 1);
        try {
            // save variables needed for cloning and remove preop
            String list = cs.getString("preop.cert.list", "");
            StringTokenizer st = new StringTokenizer(list, ",");

            while (st.hasMoreTokens()) {
                String ss = st.nextToken();
                if (ss.equals("sslserver"))
                    continue;
                cs.putString("cloning." + ss + ".nickname", cs.getString("preop.cert." + ss + ".nickname", ""));
                cs.putString("cloning." + ss + ".dn", cs.getString("preop.cert." + ss + ".dn", ""));
                cs.putString("cloning." + ss + ".keytype", cs.getString("preop.cert." + ss + ".keytype", ""));
                cs.putString("cloning." + ss + ".keyalgorithm", cs.getString("preop.cert." + ss + ".keyalgorithm", ""));
                cs.putString("cloning." + ss + ".privkey.id", cs.getString("preop.cert." + ss + ".privkey.id", ""));
                cs.putString("cloning." + ss + ".pubkey.exponent", cs.getString("preop.cert." + ss + ".pubkey.exponent", ""));
                cs.putString("cloning." + ss + ".pubkey.modulus", cs.getString("preop.cert." + ss + ".pubkey.modulus", ""));
                cs.putString("cloning." + ss + ".pubkey.encoded", cs.getString("preop.cert." + ss + ".pubkey.encoded", ""));
            }
            cs.putString("cloning.module.token", cs.getString("preop.module.token", ""));
            cs.putString("cloning.list", list);

            // more cloning variables needed for non-ca clones

            if (! type.equals("CA")) {
                String val = cs.getString("preop.ca.hostname", "");
                if (val.compareTo("") != 0) cs.putString("cloning.ca.hostname", val);

                val = cs.getString("preop.ca.httpport", "");
                if (val.compareTo("") != 0) cs.putString("cloning.ca.httpport", val);

                val =  cs.getString("preop.ca.httpsport", "");
                if (val.compareTo("") != 0) cs.putString("cloning.ca.httpsport", val);

                val = cs.getString("preop.ca.list", "");
                if (val.compareTo("") != 0) cs.putString("cloning.ca.list", val);

                val = cs.getString("preop.ca.pkcs7", "");
                if (val.compareTo("") != 0) cs.putString("cloning.ca.pkcs7", val);

                val = cs.getString("preop.ca.type", "");
                if (val.compareTo("") != 0) cs.putString("cloning.ca.type", val);
            }

            // save EC type for sslserver cert (if present)
            cs.putString("jss.ssl.sslserver.ectype", cs.getString("preop.cert.sslserver.ec.type", "ECDHE"));

            cs.removeSubStore("preop");
            cs.commit(false);

            // Create an empty file that designates the fact that although
            // this server instance has been configured, it has NOT yet
            // been restarted!
            String restart_server = instanceRoot + "/conf/"
                                  + RESTART_SERVER_AFTER_CONFIGURATION;
            if( !Utils.isNT() ) {
                Utils.exec( "touch " + restart_server );
                Utils.exec( "chmod 00660 " + restart_server );
            }

        } catch (Exception e) {
            CMS.debug("Caught exception saving preop variables: " + e);
        }

        context.put("csstate", "1");
    }

    private void setupClientAuthUser()
    {
        IConfigStore cs = CMS.getConfigStore();

        // retrieve CA subsystem certificate from the CA
        IUGSubsystem system =
          (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));
        String id = "";
        try {
            String b64 = getCASubsystemCert();
            if (b64 != null) {
                int num = cs.getInteger("preop.subsystem.count", 0);
                id = getCAUserId();
                num++;
                cs.putInteger("preop.subsystem.count", num);
                cs.putInteger("subsystem.count", num);
                IUser user = system.createUser(id);
                user.setFullName(id);
                user.setEmail("");
                user.setPassword("");
                user.setUserType("agentType");
                user.setState("1");
                user.setPhone("");
                X509CertImpl[] certs = new X509CertImpl[1];
                certs[0] = new X509CertImpl(CMS.AtoB(b64));
                user.setX509Certificates(certs);
                system.addUser(user);
                CMS.debug("DonePanel display: successfully add the user");
                system.addUserCert(user);
                CMS.debug("DonePanel display: successfully add the user certificate");
                cs.commit(false);
            }
        } catch (Exception e) {
        }

        try {
            String groupName = "Trusted Managers";
            IGroup group = system.getGroupFromName(groupName);
            if (!group.isMember(id)) {
                group.addMemberName(id);
                system.modifyGroup(group);
                CMS.debug("DonePanel display: successfully added the user to the group.");
            }
        } catch (Exception e) {
        }
    }

    private void setupDBUser(String dbuser) throws CertificateException, EUsrGrpException, LDAPException {
        IUGSubsystem system =
                (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));

        String b64 = getSubsystemCert();
        if (b64 == null) {
            CMS.debug("DonePanel setupDBUser: failed to fetch subsystem cert");
            return;
        }

        IUser user = system.createUser(dbuser);
        user.setFullName(dbuser);
        user.setEmail("");
        user.setPassword("");
        user.setUserType("agentType");
        user.setState("1");
        user.setPhone("");
        X509CertImpl[] certs = new X509CertImpl[1];
        certs[0] = new X509CertImpl(CMS.AtoB(b64));
        user.setX509Certificates(certs);
        system.addUser(user);
        CMS.debug("DonePanel setupDBUser: successfully add the user");
        system.addUserCert(user);
        CMS.debug("DonePanel setupDBUser: successfully add the user certificate");
    }

    private String getSubsystemCert() {
        IConfigStore cs = CMS.getConfigStore();
        String nickname = "";
        try {
            nickname = cs.getString("preop.cert.subsystem.nickname", "");
            String tokenname = cs.getString("preop.module.token", "");
            if (!tokenname.equals("internal") && !tokenname.equals("Internal Key Storage Token")
                    && !tokenname.equals(""))
                nickname = tokenname + ":" + nickname;
        } catch (Exception e) {
        }

        CMS.debug("DonePanel getSubsystemCert: nickname=" + nickname);
        String s = null;
        try {
            CryptoManager cm = CryptoManager.getInstance();
            org.mozilla.jss.crypto.X509Certificate cert = cm.findCertByNickname(nickname);

            if (cert == null) {
                CMS.debug("DonePanel getSubsystemCert: subsystem cert is null");
                return null;
            }

            byte[] bytes = cert.getEncoded();
            s = CryptoUtil.normalizeCertStr(CryptoUtil.base64Encode(bytes));
        } catch (Exception e) {
            CMS.debug("DonePanel getSubsystemCert: exception: " + e.toString());
        }
        return s;
    }

    private void updateOCSPConfig(HttpServletResponse response)
            throws IOException {
        IConfigStore config = CMS.getConfigStore();
        String cahost = "";
        int caport = -1;
        String sdhost = "";
        int sdport = -1;

        try {
            cahost = config.getString("preop.ca.hostname", "");
            caport = config.getInteger("preop.ca.httpsport", -1);
            sdhost = config.getString("securitydomain.host", "");
            sdport = config.getInteger("securitydomain.httpseeport", -1);
        } catch (Exception e) {
        }

        String ocsphost = CMS.getAgentHost();
        int ocspport = Integer.parseInt(CMS.getAgentPort());
        int ocspagentport = Integer.parseInt(CMS.getAgentPort());
        String session_id = CMS.getConfigSDSessionId();
        String content = "xmlOutput=true&sessionID="+session_id+"&ocsp_host="+ocsphost+"&ocsp_port="+ocspport;

        updateOCSPConfig(cahost, caport, true, content, response);
    }

    private void importCACertToOCSP() throws IOException {
        IConfigStore config = CMS.getConfigStore();

        // get certificate chain from CA
        try {
            String b64 = config.getString("preop.ca.pkcs7", "");

            if (b64.equals(""))
                throw new IOException("Failed to get certificate chain.");
  
            try {
                // this could be a chain
                X509Certificate[] certs = Cert.mapCertFromPKCS7(b64);
                X509Certificate leafCert = null;
                if (certs != null && certs.length > 0) {
                    if (certs[0].getSubjectDN().getName().equals(certs[0].getIssuerDN().getName())) {
                        leafCert = certs[certs.length - 1];
                    } else {
                        leafCert = certs[0];
                    }
 
                    IOCSPAuthority ocsp = 
                      (IOCSPAuthority)CMS.getSubsystem(IOCSPAuthority.ID);
                    IDefStore defStore = ocsp.getDefaultStore();

                    // (1) need to normalize (sort) the chain

                    // (2) store certificate (and certificate chain) into
                    // database
                    ICRLIssuingPointRecord rec = defStore.createCRLIssuingPointRecord(
                      leafCert.getSubjectDN().getName(),
                      BIG_ZERO,
                      MINUS_ONE, null, null);

                    try {
                        rec.set(ICRLIssuingPointRecord.ATTR_CA_CERT, leafCert.getEncoded());
                    } catch (Exception e) {
                        // error
                    }
                    defStore.addCRLIssuingPoint(leafCert.getSubjectDN().getName(), rec);
                    //log(ILogger.EV_AUDIT, AuditFormat.LEVEL, "Added CA certificate " + leafCert.getSubjectDN().getName());

                    CMS.debug("DonePanel importCACertToOCSP: Added CA certificate.");
                }
            } catch (Exception e) {
                throw new IOException("Failed to encode the certificate chain");
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            CMS.debug("DonePanel importCACertToOCSP: Failed to import the certificate chain into the OCSP");
            throw new IOException("Failed to import the certificate chain into the OCSP");
        }
    }

    private String getCASubsystemCert() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        String host = "";
        int port = -1;
        try {
            host = cs.getString("preop.ca.hostname", "");
            port = cs.getInteger("preop.ca.httpsadminport", -1);
        } catch (Exception e) {
        }

        return getSubsystemCert(host, port, true);
    }

    private String getCAUserId() throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        String host = "";
        int port = -1;
        try {
            host = cs.getString("preop.ca.hostname", "");
            port = cs.getInteger("preop.ca.httpsport", -1);
        } catch (Exception e) {
        }

        return "CA-" + host + "-" + port;
    }

    private void updateConnectorInfo(String ownagenthost, String ownagentsport)
      throws IOException {
        IConfigStore cs = CMS.getConfigStore();
        int port = -1;
        String url = "";
        String host = null;
        String transportCert = "";
        try {
            url = cs.getString("preop.ca.url", "");
            if (!url.equals("")) {
              host = cs.getString("preop.ca.hostname", "");
              port = cs.getInteger("preop.ca.httpsadminport", -1);
              transportCert = cs.getString("kra.transport.cert", "");
            }
        } catch (Exception e) {
        }

        if (host == null) {
          CMS.debug("DonePanel: preop.ca.url is not defined. External CA selected. No transport certificate setup is required");
        } else {
          CMS.debug("DonePanel: Transport certificate is being setup in " + url);
          String session_id = CMS.getConfigSDSessionId();
          String content = "ca.connector.KRA.enable=true&ca.connector.KRA.local=false&ca.connector.KRA.timeout=30&ca.connector.KRA.uri=/kra/agent/kra/connector&ca.connector.KRA.host="+ownagenthost+"&ca.connector.KRA.port="+ownagentsport+"&ca.connector.KRA.transportCert="+URLEncoder.encode(transportCert)+"&sessionID="+session_id; 

          updateConnectorInfo(host, port, true, content);
        }
    }

    private String getSubsystemNodeName(String type) {
        if (type.equals("CA")) {
            return "CAList";
        } else if (type.equals("KRA")) {
            return "KRAList";
        } else if (type.equals("TKS")) {
            return "TKSList";
        } else if (type.equals("OCSP")) {
            return "OCSPList";
        }

        return "";
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
            Context context) throws IOException {}

    /**
     * If validiate() returns false, this method will be called.
     */
    public void displayError(HttpServletRequest request,
            HttpServletResponse response,
            Context context) {/* This should never be called */}
}
