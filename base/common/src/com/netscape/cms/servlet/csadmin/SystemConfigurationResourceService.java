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
// (C) 2012 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.cms.servlet.csadmin;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.util.IncorrectPasswordException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISecurityDomainSessionTable;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.base.CMSException;
import com.netscape.cms.servlet.base.CMSResourceService;
import com.netscape.cms.servlet.csadmin.model.CertData;
import com.netscape.cms.servlet.csadmin.model.ConfigurationData;
import com.netscape.cms.servlet.csadmin.model.ConfigurationResponseData;
import com.netscape.cms.servlet.csadmin.model.DomainInfo;
import com.netscape.cms.servlet.csadmin.model.InstallToken;
import com.netscape.cms.servlet.csadmin.model.InstallTokenRequest;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Utils;

/**
 * @author alee
 *
 */
public class SystemConfigurationResourceService extends CMSResourceService implements SystemConfigurationResource {
    IConfigStore cs;
    String csType;
    String csState;
    boolean isMasterCA = false;
    String instanceRoot;

    public static String SUCCESS = "0";
    public static final String RESTART_SERVER_AFTER_CONFIGURATION =
            "restart_server_after_configuration";
    private Random random = null;

    public SystemConfigurationResourceService() throws EPropertyNotFound, EBaseException {
        cs = CMS.getConfigStore();
        csType = cs.getString("cs.type");
        csState = cs.getString("cs.state");
        String domainType = cs.getString("securitydomain.select", "existingdomain");
        if (csType.equals("CA") && domainType.equals("new")) {
            isMasterCA = true;
        }
        instanceRoot = cs.getString("instanceRoot");
        random = new Random();
    }

    /* (non-Javadoc)
     * @see com.netscape.cms.servlet.csadmin.SystemConfigurationResource#configure(javax.ws.rs.core.MultivaluedMap)
     */
    @Override
    public ConfigurationResponseData configure(MultivaluedMap<String, String> form) {
        ConfigurationData data = new ConfigurationData(form);
        return configure(data);
    }

    /* (non-Javadoc)
     * @see com.netscape.cms.servlet.csadmin.SystemConfigurationResource#configure(com.netscape.cms.servlet.csadmin.data.ConfigurationData)
     */
    @Override
    public ConfigurationResponseData configure(ConfigurationData data){
        if (csState.equals("1")) {
            throw new CMSException(Response.Status.BAD_REQUEST, "System is already configured");
        }

        String certList;
        try {
            certList = cs.getString("preop.cert.list");
        } catch (Exception e) {
            e.printStackTrace();
            throw new CMSException("Unable to get certList from config file");
        }

        validateData(data);
        ConfigurationResponseData response = new ConfigurationResponseData();

        // specify module and log into token
        String token = data.getToken();
        if (token == null) {
            token = ConfigurationData.TOKEN_DEFAULT;
        }
        cs.putString("preop.module.token", token);

        if (! token.equals(ConfigurationData.TOKEN_DEFAULT)) {
            try {
                CryptoManager cryptoManager = CryptoManager.getInstance();
                CryptoToken ctoken = cryptoManager.getTokenByName(token);
                String tokenpwd = data.getTokenPassword();
                ConfigurationUtils.loginToken(ctoken, tokenpwd);
            } catch (NotInitializedException e) {
                throw new CMSException("Token is not initialized");
            } catch (NoSuchTokenException e) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Invalid Token provided. No such token.");
            } catch (TokenException e) {
                e.printStackTrace();
                throw new CMSException("Token Exception" + e);
            } catch (IncorrectPasswordException e) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Incorrect Password provided for token.");
            }
        }

        //configure security domain
        String securityDomainType = data.getSecurityDomainType();
        String securityDomainName = data.getSecurityDomainName();
        String securityDomainURL = data.getSecurityDomainUri();
        String domainXML = null;
        if (securityDomainType.equals(ConfigurationData.NEW_DOMAIN)) {
            cs.putString("preop.securitydomain.select", "new");
            cs.putString("securitydomain.select", "new");
            cs.putString("preop.securitydomain.name", securityDomainName);
            cs.putString("securitydomain.name", securityDomainName);
            cs.putString("securitydomain.host", CMS.getEENonSSLHost());
            cs.putString("securitydomain.httpport", CMS.getEENonSSLPort());
            cs.putString("securitydomain.httpsagentport", CMS.getAgentPort());
            cs.putString("securitydomain.httpseeport", CMS.getEESSLPort());
            cs.putString("securitydomain.httpsadminport", CMS.getAdminPort());
            cs.putString("preop.cert.subsystem.type", "local");
            cs.putString("preop.cert.subsystem.profile", "subsystemCert.profile");
        } else {
            cs.putString("preop.securitydomain.select", "existing");
            cs.putString("securitydomain.select", "existing");
            cs.putString("preop.cert.subsystem.type", "remote");
            cs.putString("preop.cert.subsystem.profile", "caInternalAuthSubsystemCert");

            // contact and log onto security domain
            URL secdomainURL;
            String host;
            int port;
            try {
                secdomainURL = new URL(securityDomainURL);
                host = secdomainURL.getHost();
                port = secdomainURL.getPort();
                cs.putString("securitydomain.host", host);
                cs.putInteger("securitydomain.httpsadminport",port);
                ConfigurationUtils.importCertChain(host, port, "/ca/admin/ca/getCertChain", "securitydomain");
            } catch (Exception e) {
                e.printStackTrace();
                throw new CMSException("Failed to import certificate chain from security domain master: " + e);
            }

            // log onto security domain and get token
            String user = data.getSecurityDomainUser();
            String pass = data.getSecurityDomainPassword();
            String installToken;
            try {
                installToken = ConfigurationUtils.getInstallToken(host, port, user, pass);
            } catch (Exception e) {
                e.printStackTrace();
                throw new CMSException("Failed to obtain installation token from security domain: " + e);
            }

            if (installToken == null) {
                throw new CMSException("Failed to obtain installation token from security domain");
            }
            CMS.setConfigSDSessionId(installToken);

            try {
                domainXML = ConfigurationUtils.getDomainXML(host, port, true);
                ConfigurationUtils.getSecurityDomainPorts(domainXML, host, port);
            } catch (Exception e) {
                e.printStackTrace();
                throw new CMSException("Failed to obtain security domain decriptor from security domain master: " + e);
            }
        }

        cs.putString("preop.subsystem.name", data.getSubsystemName());

        // is this a clone of another subsystem?
        if (data.getIsClone().equals("false")) {
            cs.putString("preop.subsystem.select", "new");
            cs.putString("subsystem.select", "New");
        } else {
            cs.putString("preop.subsystem.select", "clone");
            cs.putString("subsystem.select", "Clone");

            StringTokenizer t = new StringTokenizer(certList, ",");
            while (t.hasMoreTokens()) {
                String tag = t.nextToken();
                if (tag.equals("sslserver")) {
                    cs.putBoolean("preop.cert." + tag + ".enable", true);
                } else {
                    cs.putBoolean("preop.cert." + tag + ".enable", false);
                }
            }

            String cloneUri = data.getCloneUri();
            URL url = null;
            try {
                url = new URL(cloneUri);
            } catch (MalformedURLException e) {
                // should not reach here as this check is done in validate()
            }
            String masterHost = url.getHost();
            int masterPort = url.getPort();

            // check and store cloneURI information
            boolean validCloneUri;
            try {
                validCloneUri = ConfigurationUtils.isValidCloneURI(domainXML, masterHost, masterPort);
            } catch (Exception e) {
                e.printStackTrace();
                throw new CMSException("Error in determining whether clone URI is valid");
            }

            if (!validCloneUri) {
                throw new CMSException(Response.Status.BAD_REQUEST,
                        "Invalid clone URI provided.  Does not match the available subsystems in the security domain");
            }

            if (csType.equals("CA")) {
                try {
                    ConfigurationUtils.importCertChain(masterHost, masterPort, "/ca/ee/ca/getCertChain", "clone");
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new CMSException("Failed to import certificate chain from master" + e);
                }
            }

            try {
                ConfigurationUtils.getConfigEntriesFromMaster();
            } catch (Exception e) {
                e.printStackTrace();
                throw new CMSException("Failed to obtain configuration entries from the master for cloning " + e);
            }

            // restore certs from P12 file
            if (token.equals(ConfigurationData.TOKEN_DEFAULT)) {
                String p12File = data.getP12File();
                String p12Pass = data.getP12Password();
                try {
                    ConfigurationUtils.restoreCertsFromP12(p12File, p12Pass);
                } catch (Exception e) {
                    e.printStackTrace();
                    throw new CMSException("Failed to restore certificates from p12 file" + e);
                }
            }

            boolean cloneReady = ConfigurationUtils.isCertdbCloned();
            if (!cloneReady) {
                CMS.debug("clone does not have all the certificates.");
                throw new CMSException("Clone does not have all the required certificates");
            }
        }

        // Hierarchy Panel
        if (csType.equals("CA") && data.getIsClone().equals("false")) {
            if (data.getHierarchy().equals("root")) {
                cs.putString("preop.hierarchy.select", "root");
                cs.putString("hierarchy.select", "Root");
                cs.putString("preop.ca.type", "sdca");
            } else if (data.getHierarchy().equals("join")) {
                cs.putString("preop.cert.signing.type", "remote");
                cs.putString("preop.hierarchy.select", "join");
                cs.putString("hierarchy.select", "Subordinate");
            } else {
                throw new CMSException(Response.Status.BAD_REQUEST, "Invalid hierarchy provided");
            }
        }

        // Database Panel
        cs.putString("internaldb.ldapconn.host", data.getDsHost());
        cs.putString("internaldb.ldapconn.port", data.getDsPort());
        cs.putString("internaldb.database", data.getDatabase());
        cs.putString("internaldb.basedn", data.getBaseDN());
        cs.putString("internaldb.ldapauth.bindDN", data.getBindDN());
        cs.putString("internaldb.ldapconn.secureConn", (data.getSecureConn().equals("on") ? "true" : "false"));
        cs.putString("preop.database.removeData", data.getRemoveData());

        try {
            cs.commit(false);
        } catch (EBaseException e2) {
            e2.printStackTrace();
            throw new CMSException("Unable to commit config parameters to file");
        }

        if (data.getIsClone().equals("true")) {
            String masterhost = "";
            String masterport = "";
            String masterbasedn = "";
            String realhostname = "";
            try {
                masterhost = cs.getString("preop.internaldb.master.ldapconn.host", "");
                masterport = cs.getString("preop.internaldb.master.ldapconn.port", "");
                masterbasedn = cs.getString("preop.internaldb.master.basedn", "");
                realhostname = cs.getString("machineName", "");
            } catch (Exception e) {
            }

            if (masterhost.equals(realhostname) && masterport.equals(data.getDsPort())) {
                throw new CMSException(Response.Status.BAD_REQUEST,
                        "Master and clone must not share the same internal database");
            }

            if (!masterbasedn.equals(data.getBaseDN())) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Master and clone should have the same base DN");
            }

            String masterReplicationPort = data.getMasterReplicationPort();
            if ((masterReplicationPort != null) && (!masterReplicationPort.equals(""))) {
                cs.putString("internaldb.ldapconn.masterReplicationPort", masterReplicationPort);
            } else {
                cs.putString("internaldb.ldapconn.masterReplicationPort", masterport);
            }

            String cloneReplicationPort = data.getCloneReplicationPort();
            if ((cloneReplicationPort == null) || (cloneReplicationPort.length() == 0)) {
                cloneReplicationPort = data.getDsPort();
            }
            cs.putString("internaldb.ldapconn.cloneReplicationPort", cloneReplicationPort);

            String replicationSecurity = data.getReplicationSecurity();
            if ((cloneReplicationPort == data.getDsPort()) && (data.getSecureConn().equals("on"))) {
                replicationSecurity = "SSL";
            } else if (replicationSecurity == null) {
                replicationSecurity = "None";
            }
            cs.putString("internaldb.ldapconn.replicationSecurity", replicationSecurity);
        }

        try {
            /* BZ 430745 create password for replication manager */
            String replicationpwd = Integer.toString(new Random().nextInt());

            IConfigStore psStore = null;
            String passwordFile = null;
            passwordFile = cs.getString("passwordFile");
            psStore = CMS.createFileConfigStore(passwordFile);
            psStore.putString("internaldb", data.getBindpwd());
            psStore.putString("replicationdb", replicationpwd);
            psStore.commit(false);

            ConfigurationUtils.populateDB();

            cs.putString("preop.internaldb.replicationpwd", replicationpwd);
            cs.putString("preop.database.removeData", "false");
            cs.commit(false);

            ConfigurationUtils.reInitSubsystem(csType);
            ConfigurationUtils.populateIndexes();

            if (data.getIsClone().equals("true")) {
                CMS.debug("Start setting up replication.");
                ConfigurationUtils.setupReplication();
                ConfigurationUtils.reInitSubsystem(csType);
            }
        } catch (Exception e) {
            throw new CMSException("Error in populating database" + e);
        }

        // SizePanel, NamePanel, CertRequestPanel
        //handle the CA URL
        try {
            if ((data.getHierarchy() == null) || (data.getHierarchy().equals("join"))) {
                String url = data.getIssuingCA();
                if (url.equals("External CA")) {
                    CMS.debug("external CA selected");
                    cs.putString("preop.ca.type", "otherca");
                    cs.putString("preop.ca.pkcs7", "");
                    cs.putInteger("preop.ca.certchain.size", 0);
                    if (csType.equals("CA")) {
                        cs.putString("preop.cert.signing.type", "remote");
                    }
                } else {
                    CMS.debug("local CA selected");
                    url = url.substring(url.indexOf("https"));
                    cs.putString("preop.ca.url", url);

                    URL urlx = new URL(url);
                    String host = urlx.getHost();
                    int port = urlx.getPort();
                    int admin_port = ConfigurationUtils.getPortFromSecurityDomain(domainXML,
                            host, port, "CA", "SecurePort", "SecureAdminPort");

                    cs.putString("preop.ca.type", "sdca");
                    cs.putString("preop.ca.hostname", host);
                    cs.putInteger("preop.ca.httpsport", port);
                    cs.putInteger("preop.ca.httpsadminport", admin_port);

                    if (!data.getIsClone().equals("true")) {
                       ConfigurationUtils.importCertChain(host, admin_port, "/ca/admin/ca/getCertChain", "ca");
                    }

                    if (csType.equals("CA")) {
                        cs.putString("preop.cert.signing.type", "remote");
                        cs.putString("preop.cert.signing.profile","caInstallCACert");
                    }
                }
            }
        } catch (Exception e) {
            throw new CMSException("Error in obtaining certificate chain from issuing CA: " + e);
        }

        boolean hasSigningCert = false;
        Vector<Cert> certs = new Vector<Cert>();
        try {
            StringTokenizer t = new StringTokenizer(certList, ",");
            while (t.hasMoreTokens()) {
                String ct = t.nextToken();
                boolean enable = cs.getBoolean("preop.cert." + ct + ".enable", true);
                if (!enable) continue;

                Collection<CertData> certData = data.getSystemCerts();
                Iterator<CertData> iterator = certData.iterator();
                CertData cdata = null;
                while (iterator.hasNext()) {
                    cdata = iterator.next();
                    if (cdata.getTag().equals(ct)) break;
                }

                String keytype = (cdata.getKeyType() != null) ? cdata.getKeyType() : "rsa";

                String keyalgorithm = cdata.getKeyAlgorithm();
                if (keyalgorithm == null) {
                    keyalgorithm = (keytype.equals("ecc")) ? "SHA256withEC" : "SHA256withRSA";
                }

                String signingalgorithm = (cdata.getSigningAlgorithm() != null)?  cdata.getSigningAlgorithm(): keyalgorithm ;
                String nickname = (cdata.getNickname() != null) ? cdata.getNickname() :
                    cs.getString("preop.cert." + ct + ".nickname");
                String dn = (cdata.getSubjectDN() != null)? cdata.getSubjectDN() :
                    cs.getString("preop.cert." + ct + ".dn");


                cs.putString("preop.cert." + ct + ".keytype", keytype);
                cs.putString("preop.cert." + ct + ".keyalgorithm", keyalgorithm);
                cs.putString("preop.cert." + ct + ".signingalgorithm", signingalgorithm);
                cs.putString("preop.cert." + ct + ".nickname", nickname);
                cs.putString("preop.cert." + ct + ".dn", dn);

                if (data.getStepTwo() == null) {
                    if (keytype.equals("ecc")) {
                        String curvename = (cdata.getKeyCurveName() != null) ?
                                cdata.getKeyCurveName() : cs.getString("keys.ecc.curve.default");
                        cs.putString("preop.cert." + ct + ".curvename.name", curvename);
                        ConfigurationUtils.createECCKeyPair(token, curvename, cs, ct);
                    } else {
                        String keysize = cdata.getKeySize() != null ? cdata.getKeySize() : cs
                                .getString("keys.rsa.keysize.default");
                        cs.putString("preop.cert." + ct + ".keysize.size", keysize);
                        ConfigurationUtils.createRSAKeyPair(token, Integer.parseInt(keysize), cs, ct);
                    }
                } else {
                    CMS.debug("configure(): step two selected.  keys will not be generated");
                }

                String tokenName = cdata.getToken() != null ? cdata.getToken() : token;
                Cert certObj = new Cert(tokenName, nickname, ct);
                certObj.setDN(dn);
                certObj.setSubsystem(cs.getString("preop.cert." + ct + ".subsystem"));
                certObj.setType(cs.getString("preop.cert." + ct + ".type"));

                if (data.getStepTwo() == null) {
                    ConfigurationUtils.configCert(null, null, null, certObj, null);
                } else {
                    String subsystem = cs.getString("preop.cert." + ct + ".subsystem");
                    String certStr = cs.getString(subsystem + "." + ct + ".cert" );
                    certObj.setCert(certStr);
                    CMS.debug("Step 2: certStr for " + ct + " is " + certStr);
                }
                ConfigurationUtils.handleCertRequest(cs, ct, certObj);

                if (data.getIsClone().equals("true")) {
                    ConfigurationUtils.updateCloneConfig();
                }

                // to determine if we have the signing cert when using an external ca
                // this will only execute on a ca
                String b64 = cdata.getCert();
                if (ct.equals("signing") && (b64!= null) && (b64.length()>0) && (!b64.startsWith("..."))) {
                    hasSigningCert = true;
                    if (data.getIssuingCA().equals("External CA")) {
                        b64 = CryptoUtil.stripCertBrackets(b64.trim());
                        certObj.setCert(CryptoUtil.normalizeCertStr(b64));

                        if (cdata.getCertChain() != null) {
                            certObj.setCertChain(cdata.getCertChain());
                        } else {
                            throw new CMSException(Response.Status.BAD_REQUEST, "CertChain not provided");
                        }
                    }
                }

                certs.addElement(certObj);
            }
            // make sure to commit changes here for step 1
            cs.commit(false);

        } catch (NumberFormatException e) {
            // move these validations to validate()?
            throw new CMSException(Response.Status.BAD_REQUEST, "Non-integer value for key size");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new CMSException(Response.Status.BAD_REQUEST, "Invalid algorithm " + e);
        } catch (Exception e) {
            e.printStackTrace();
            throw new CMSException("Error in setting certificate names and key sizes: " + e);
        }

        // submitting to external ca
        if ((data.getIssuingCA()!= null) && data.getIssuingCA().equals("External CA") && (!hasSigningCert)) {
            response.setSystemCerts(certs);
            return response;
        }

        Enumeration<Cert> c = certs.elements();
        while (c.hasMoreElements()) {
            Cert cert = c.nextElement();
            int ret;
            try {
                ret = ConfigurationUtils.handleCerts(cert);
                ConfigurationUtils.setCertPermissions(cert.getCertTag());
            } catch (Exception e) {
                e.printStackTrace();
                throw new CMSException("Error in confguring system certificates" + e);
            }
            if (ret != 0) {
                throw new CMSException("Error in confguring system certificates");
            }
        }
        response.setSystemCerts(certs);

        // BackupKeyCertPanel/SavePKCS12Panel
        if (data.getBackupKeys().equals("true")) {
            try {
                ConfigurationUtils.backupKeys(data.getBackupPassword(), data.getBackupFile());
            } catch (Exception e) {
                e.printStackTrace();
                throw new CMSException("Error in creating pkcs12 to backup keys and certs: " + e);
            }
        }

        // AdminPanel
        if (!data.getIsClone().equals("true")) {
            try {
                X509CertImpl admincerts[] = new X509CertImpl[1];
                ConfigurationUtils.createAdmin(data.getAdminUID(), data.getAdminEmail(),
                        data.getAdminName(), data.getAdminPassword());
                if (csType.equals("CA")) {
                    ConfigurationUtils.createAdminCertificate(data.getAdminCertRequest(),
                            data.getAdminCertRequestType(), data.getAdminSubjectDN());

                    String serialno = cs.getString("preop.admincert.serialno.0");
                    ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(ICertificateAuthority.ID);
                    ICertificateRepository repo = ca.getCertificateRepository();
                    admincerts[0] = repo.getX509Certificate(new BigInteger(serialno, 16));
                } else {
                    String type = cs.getString("preop.ca.type", "");
                    String ca_hostname = "";
                    int ca_port = -1;
                    if (type.equals("sdca")) {
                        ca_hostname = cs.getString("preop.ca.hostname");
                        ca_port = cs.getInteger("preop.ca.httpsport");
                    } else {
                        ca_hostname = cs.getString("securitydomain.host", "");
                        ca_port = cs.getInteger("securitydomain.httpseeport");
                    }
                    String b64 = ConfigurationUtils.submitAdminCertRequest(ca_hostname, ca_port,
                            data.getAdminProfileID(), data.getAdminCertRequestType(),
                            data.getAdminCertRequest(), data.getAdminSubjectDN());
                    b64 = CryptoUtil.stripCertBrackets(b64.trim());
                    byte[] b = CryptoUtil.base64Decode(b64);
                    admincerts[0] = new X509CertImpl(b);
                }
                CMS.reinit(IUGSubsystem.ID);

                IUGSubsystem ug = (IUGSubsystem) CMS.getSubsystem(IUGSubsystem.ID);
                IUser user = ug.getUser(data.getAdminUID());
                user.setX509Certificates(admincerts);
                ug.addUserCert(user);
                response.setAdminCert(admincerts[0]);

            } catch (Exception e) {
                e.printStackTrace();
                throw new CMSException("Error in creating admin user: " + e);
            }
        }

        // Done Panel
        // Create or update security domain
        try {
            if (securityDomainType.equals(ConfigurationData.NEW_DOMAIN)) {
                ConfigurationUtils.createSecurityDomain();
            } else {
                ConfigurationUtils.updateSecurityDomain();
            }
            cs.putString("service.securityDomainPort", CMS.getAgentPort());
            cs.putString("securitydomain.store", "ldap");
            cs.commit(false);
        } catch (Exception e) {
            e.printStackTrace();
            throw new CMSException("Error while updating security domain: " + e);
        }

        // need to push connector information to the CA
        String ca_host="";
        try {
            ca_host = cs.getString("preop.ca.hostname", "");
        } catch (EBaseException e) {
            e.printStackTrace();
        }

        // need to push connector information to the CA
        try {
            if (csType.equals("KRA") && (!ca_host.equals(""))) {
                ConfigurationUtils.updateConnectorInfo(CMS.getAgentHost(), CMS.getAgentPort());
                ConfigurationUtils.setupClientAuthUser();
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new CMSException("Errors in pushing KRA connector information to the CA: " + e);
        }

        // import the CA certificate into the OCSP
        // configure the CRL Publishing to OCSP in CA
        try {
            if (csType.equals("OCSP") && (!ca_host.equals(""))) {
                CMS.reinit(IOCSPAuthority.ID);
                ConfigurationUtils.importCACertToOCSP();
                ConfigurationUtils.updateOCSPConfig();
                ConfigurationUtils.setupClientAuthUser();
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new CMSException("Errors in configuring CA publishing to OCSP: " + e);
        }

        if (!data.getIsClone().equals("true")) {
            try {
                if (csType.equals("CA") || csType.equals("KRA")) {
                     ConfigurationUtils.updateNextRanges();
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new CMSException("Errors in updating next serial number ranges in DB: " + e);
            }
        }

        try {
            if (data.getIsClone().equals("true") && csType.equalsIgnoreCase("CA")
                    && ConfigurationUtils.isSDHostDomainMaster(cs)) {
                // cloning a domain master CA, the clone is also master of its domain
                cs.putString("securitydomain.host", CMS.getEEHost());
                cs.putString("securitydomain.httpport", CMS.getEENonSSLPort());
                cs.putString("securitydomain.httpsadminport", CMS.getAdminPort());
                cs.putString("securitydomain.httpsagentport", CMS.getAgentPort());
                cs.putString("securitydomain.httpseeport", CMS.getEESSLPort());
                cs.putString("securitydomain.select", "new");

            }
        } catch (Exception e1) {
            e1.printStackTrace();
            throw new CMSException("Errors in determining if security domain host is a master CA");
        }

        try {
            String dbuser = csType + "-" + CMS.getEEHost() + "-" + CMS.getEESSLPort();
            if (! securityDomainType.equals(ConfigurationData.NEW_DOMAIN)) {
                ConfigurationUtils.setupDBUser(dbuser);
            }
            IUGSubsystem system = (IUGSubsystem) (CMS.getSubsystem(IUGSubsystem.ID));
            IUser user = system.getUser(dbuser);
            system.addCertSubjectDN(user);
        } catch (Exception e) {
            e.printStackTrace();
            throw new CMSException("Errors in creating or updating dbuser: " + e);
        }

        cs.putInteger("cs.state", 1);

        // update serial numbers for clones

        // save some variables, remove remaining preops
        try {
            ConfigurationUtils.removePreopConfigEntries();
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new CMSException("Errors when removing preop config entries: " + e);
        }

        // Create an empty file that designates the fact that although
        // this server instance has been configured, it has NOT yet
        // been restarted!
        String restart_server = instanceRoot + "/conf/" + RESTART_SERVER_AFTER_CONFIGURATION;
        Utils.exec("touch " + restart_server);
        Utils.exec("chmod 00660 " + restart_server);

        response.setStatus(SUCCESS);
        return response;
    }

    private void validateData(ConfigurationData data) {
        // get required info from CS.cfg
        String preopPin;
        try {
            preopPin = cs.getString("preop.pin");
        } catch (Exception e) {
            CMS.debug("validateData: Failed to get required config form CS.cfg");
            e.printStackTrace();
            throw new CMSException("Unable to retrieve required configuration from configuration files");
        }

        // get the preop pin and validate it
        String pin = data.getPin();
        if (pin == null) {
            throw new CMSException(Response.Status.BAD_REQUEST, "No preop pin provided");
        }
        if (!preopPin.equals(pin)) {
            throw new CMSException(Response.Status.BAD_REQUEST, "Incorrect pin provided");
        }

        // validate security domain settings
        String domainType = data.getSecurityDomainType();
        if (domainType == null) {
            throw new CMSException(Response.Status.BAD_REQUEST, "Security Domain Type not provided");
        }

        if (domainType.equals(ConfigurationData.NEW_DOMAIN)) {
            if (!csType.equals("CA")) {
                throw new CMSException(Response.Status.BAD_REQUEST, "New Domain is only valid for CA subsytems");
            }
            if (data.getSecurityDomainName() == null) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Security Domain Name is not provided");
            }
        } else if (domainType.equals(ConfigurationData.EXISTING_DOMAIN)) {
            String domainURI = data.getSecurityDomainUri();
            if (domainURI == null) {
                throw new CMSException(Response.Status.BAD_REQUEST,
                        "Existing security domain requested, but no security domain URI provided");
            }

            try {
                @SuppressWarnings("unused")
                URL admin_u = new URL(domainURI);  // check for invalid URL
            } catch (MalformedURLException e) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Invalid security domain URI");
            }
            if ((data.getSecurityDomainUser() == null) || (data.getSecurityDomainPassword() == null)) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Security domain user or password not provided");
            }

        } else {
            throw new CMSException(Response.Status.BAD_REQUEST, "Invalid security domain URI provided");
        }

        if ((data.getSubsystemName() == null) || (data.getSubsystemName().length() ==0)) {
            throw new CMSException(Response.Status.BAD_REQUEST, "Invalid or no subsystem name provided");
        }

        if ((data.getIsClone() != null) && (data.getIsClone().equals("true"))) {
            String cloneUri = data.getCloneUri();
            if (cloneUri == null) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Clone selected, but no clone URI provided");
            }
            try {
                @SuppressWarnings("unused")
                URL url = new URL(cloneUri); // check for invalid URL
                // confirm protocol is https
            } catch (MalformedURLException e) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Invalid clone URI");
            }

            if (data.getToken().equals(ConfigurationData.TOKEN_DEFAULT)) {
                if (data.getP12File() == null) {
                    throw new CMSException(Response.Status.BAD_REQUEST, "P12 filename not provided");
                }

                if (data.getP12Password() == null) {
                    throw new CMSException(Response.Status.BAD_REQUEST, "P12 password not provided");
                }
            }
        } else {
            data.setIsClone("false");
        }

        String dsHost = data.getDsHost();
        if (dsHost == null || dsHost.length() == 0) {
            throw new CMSException(Response.Status.BAD_REQUEST, "Internal database host not provided");
        }

        try {
            Integer.parseInt(data.getDsPort());  // check for errors
        } catch (NumberFormatException e) {
            throw new CMSException(Response.Status.BAD_REQUEST, "Internal database port is invalid");
        }

        String basedn = data.getBaseDN();
        if (basedn == null || basedn.length() == 0) {
            throw new CMSException(Response.Status.BAD_REQUEST, "Internal database basedn not provided");
        }

        String binddn = data.getBindDN();
        if (binddn == null || binddn.length() == 0) {
            throw new CMSException(Response.Status.BAD_REQUEST, "Internal database basedn not provided");
        }

        String database = data.getDatabase();
        if (database == null || database.length() == 0) {
            throw new CMSException(Response.Status.BAD_REQUEST, "Internal database database name not provided");
        }

        String bindpwd = data.getBindpwd();
        if (bindpwd == null || bindpwd.length() == 0) {
            throw new CMSException(Response.Status.BAD_REQUEST, "Internal database database name not provided");
        }

        String masterReplicationPort = data.getMasterReplicationPort();
        if (masterReplicationPort != null && masterReplicationPort.length() > 0) {
            try {
                Integer.parseInt(masterReplicationPort); // check for errors
            } catch (NumberFormatException e) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Master replication port is invalid");
            }
        }

        String cloneReplicationPort = data.getCloneReplicationPort();
        if (cloneReplicationPort != null && cloneReplicationPort.length() > 0) {
            try {
                Integer.parseInt(cloneReplicationPort); // check for errors
            } catch (Exception e) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Clone replication port is invalid");
            }
        }

        if ((data.getBackupKeys() != null) && data.getBackupKeys().equals("true")) {
            if ((data.getBackupFile() == null) || (data.getBackupFile().length()<=0)) {
                //TODO: also check for valid path, perhaps by touching file there
                throw new CMSException(Response.Status.BAD_REQUEST, "Invalid key backup file name");
            }

            if ((data.getBackupPassword() == null) || (data.getBackupPassword().length()<=8)) {
                throw new CMSException(Response.Status.BAD_REQUEST, "key backup password must be at least 8 characters");
            }
        } else {
            data.setBackupKeys("false");
        }

        if (csType.equals("CA") && (data.getHierarchy() == null)) {
            throw new CMSException(Response.Status.BAD_REQUEST, "Hierarchy is requred for CA, not provided");
        }

        if (data.getIsClone().equals("false")) {
            if ((data.getAdminUID() == null) || (data.getAdminUID().length()==0)) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Admin UID not provided");
            }
            if ((data.getAdminPassword() == null) || (data.getAdminPassword().length()==0)) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Admin Password not provided");
            }
            if ((data.getAdminEmail() == null) || (data.getAdminEmail().length()==0)) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Admin UID not provided");
            }
            if ((data.getAdminName() == null) || (data.getAdminName().length()==0)) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Admin name not provided");
            }
            if ((data.getAdminCertRequest() == null) || (data.getAdminCertRequest().length()==0)) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Admin cert request not provided");
            }
            if ((data.getAdminCertRequestType() == null) || (data.getAdminCertRequestType().length()==0)) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Admin cert request type not provided");
            }
            if ((data.getAdminSubjectDN() == null) || (data.getAdminSubjectDN().length()==0)) {
                throw new CMSException(Response.Status.BAD_REQUEST, "Admin subjectDN not provided");
            }
        }

    }

    @Override
    public InstallToken getInstallToken(InstallTokenRequest data) {
        // TODO Figure out how to do authentication here based on user/pass
        // For now, allow all user/pass to be valid
        CMS.debug("getInstallToken(): starting");
        String user = data.getUser();
        String host = data.getHost();
        String subsystem = data.getSubsystem();
        String groupname = ConfigurationUtils.getGroupName(user, subsystem);

        // assign cookie
        long num = random.nextLong();
        String cookie = num + "";
        ISecurityDomainSessionTable ctable = CMS.getSecurityDomainSessionTable();
        String ip;
        try {
            ip = InetAddress.getByName(host).toString();
        } catch (UnknownHostException e) {
            throw new CMSException(Response.Status.BAD_REQUEST, "Unable to resolve host " + host +
                    "to an IP address: " + e);
        }
        int index = ip.indexOf("/");
        if (index > 0)  ip = ip.substring(index + 1);

        ctable.addEntry(cookie, ip, user, groupname);

        return new InstallToken(cookie);
    }

    @Override
    public DomainInfo getDomainInfo() {
        // TODO Auto-generated method stub for a RESTful method that returns the security domain
        return null;
    }

}
