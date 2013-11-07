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
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Random;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.UriInfo;

import netscape.security.x509.X509CertImpl;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.util.IncorrectPasswordException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.EPropertyNotFound;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.certsrv.system.ConfigurationResponse;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.certsrv.system.SystemConfigResource;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Utils;

/**
 * @author alee
 *
 */
public class SystemConfigService extends PKIService implements SystemConfigResource {
    @Context
    private UriInfo uriInfo;

    @Context
    private HttpHeaders headers;

    @Context
    private Request request;

    @Context
    private HttpServletRequest servletRequest;

    IConfigStore cs;
    String csType;
    String csSubsystem;
    String csState;
    boolean isMasterCA = false;
    String instanceRoot;

    public static String SUCCESS = "0";
    public static final String RESTART_SERVER_AFTER_CONFIGURATION =
            "restart_server_after_configuration";

    public SystemConfigService() throws EPropertyNotFound, EBaseException {
        cs = CMS.getConfigStore();
        csType = cs.getString("cs.type");
        csSubsystem = csType.toLowerCase();
        csState = cs.getString("cs.state");
        String domainType = cs.getString("securitydomain.select", "existingdomain");
        if (csType.equals("CA") && domainType.equals("new")) {
            isMasterCA = true;
        }
        instanceRoot = cs.getString("instanceRoot");
    }

    /* (non-Javadoc)
     * @see com.netscape.cms.servlet.csadmin.SystemConfigurationResource#configure(javax.ws.rs.core.MultivaluedMap)
     */
    @Override
    public ConfigurationResponse configure(MultivaluedMap<String, String> form) {
        ConfigurationRequest data = new ConfigurationRequest(form);
        return configure(data);
    }

    /* (non-Javadoc)
     * @see com.netscape.cms.servlet.csadmin.SystemConfigurationResource#configure(com.netscape.cms.servlet.csadmin.data.ConfigurationData)
     */
    @Override
    public ConfigurationResponse configure(ConfigurationRequest data){
        if (csState.equals("1")) {
            throw new BadRequestException("System is already configured");
        }

        String certList;
        try {
            certList = cs.getString("preop.cert.list");
        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException("Unable to get certList from config file");
        }

        CMS.debug("SystemConfigService(): configure() called");
        CMS.debug(data.toString());

        validateData(data);
        ConfigurationResponse response = new ConfigurationResponse();

        if (data.getStandAlone() && data.getStepTwo()) {
                // Stand-alone PKI (Step 2)
                // Special case to import the external CA and its Chain
                certList = "external_signing" + "," + certList;
        }

        // specify module and log into token
        CMS.debug("=== Token Panel ===");
        String token = data.getToken();
        if (token == null) {
            token = ConfigurationRequest.TOKEN_DEFAULT;
        }
        tokenPanel(data, token);

        //configure security domain
        CMS.debug("=== Security Domain Panel ===");
        String securityDomainType = data.getSecurityDomainType();
        String domainXML = securityDomainPanel(data, securityDomainType);

        //subsystem panel
        CMS.debug("=== Subsystem Panel ===");
        cs.putString("preop.subsystem.name", data.getSubsystemName());

        // is this a clone of another subsystem?
        if (data.getIsClone().equals("false")) {
            cs.putString("preop.subsystem.select", "new");
            cs.putString("subsystem.select", "New");
        } else {
            cs.putString("preop.subsystem.select", "clone");
            cs.putString("subsystem.select", "Clone");
            getCloningData(data, certList, token, domainXML);
        }

        // Hierarchy Panel
        CMS.debug("=== Hierarchy Panel ===");
        hierarchyPanel(data);

        // TPS Panels
        if (csType.equals("TPS")) {

            // get subsystem certificate nickname
            String subsystemNick = null;
            for (SystemCertData cdata: data.getSystemCerts()) {
                if (cdata.getTag().equals("subsystem")) {
                    subsystemNick = cdata.getNickname();
                    break;
                }
            }
            if ((subsystemNick == null) || subsystemNick.isEmpty()) {
                throw new BadRequestException("No nickname provided for subsystem certificate");
            }

            // CA Info Panel
            caInfoPanel(data, subsystemNick);

            // retrieve and import CA cert

            // TKS Info Panel
            tksInfoPanel(data, subsystemNick);

            //DRM Info Panel
            kraInfoPanel(data, subsystemNick);

            //AuthDBPanel
            ConfigurationUtils.updateAuthdbInfo(data.getAuthdbBaseDN(),
                    data.getAuthdbHost(), data.getAuthdbPort(),
                    data.getAuthdbSecureConn());

        }

        // Database Panel
        CMS.debug("=== Database Panel ===");
        databasePanel(data);

        // SizePanel, NamePanel, CertRequestPanel
        //handle the CA URL
        CMS.debug("=== Size Panel, Name Panel, CertRequest Panel ===");
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
            throw new PKIException("Error in obtaining certificate chain from issuing CA: " + e);
        }

        boolean generateServerCert = data.getGenerateServerCert().equalsIgnoreCase("false")? false : true;
        boolean hasSigningCert = false;
        Vector<Cert> certs = new Vector<Cert>();
        try {
            StringTokenizer t = new StringTokenizer(certList, ",");
            while (t.hasMoreTokens()) {
                String ct = t.nextToken();
                String certStr;
                boolean enable = cs.getBoolean("preop.cert." + ct + ".enable", true);
                if (!enable) continue;

                Collection<SystemCertData> certData = data.getSystemCerts();
                Iterator<SystemCertData> iterator = certData.iterator();
                SystemCertData cdata = null;
                boolean cdata_found = false;
                while (iterator.hasNext()) {
                    cdata = iterator.next();
                    if (cdata.getTag().equals(ct)) {
                        cdata_found = true;
                        CMS.debug("Found data for '" + ct + "'");
                        break;
                    }
                }
                if (!cdata_found) {
                    CMS.debug("No data for '" + ct + "' was found!");
                    throw new BadRequestException("No data for '" + ct + "' was found!");
                }

                if (data.getStandAlone() && data.getStepTwo()) {
                    // Stand-alone PKI (Step 2)
                    if (ct.equals("external_signing")) {
                        String b64 = cdata.getCert();
                        if ((b64!= null) && (b64.length()>0) && (!b64.startsWith("..."))) {
                            hasSigningCert = true;
                            if (data.getIssuingCA().equals("External CA")) {
                                String nickname = (cdata.getNickname() != null) ? cdata.getNickname() : "caSigningCert External CA";
                                String tokenName = cdata.getToken() != null ? cdata.getToken() : token;
                                Cert certObj = new Cert(tokenName, nickname, ct);
                                ConfigurationUtils.setExternalCACert(b64, csSubsystem, cs, certObj);
                                CMS.debug("Step 2:  certStr for '" + ct + "' is " + b64);
                                String certChainStr = cdata.getCertChain();
                                if (certChainStr != null) {
                                    ConfigurationUtils.setExternalCACertChain(certChainStr, csSubsystem, cs, certObj);
                                    CMS.debug("Step 2:  certChainStr for '" + ct + "' is " + certChainStr);
                                    certs.addElement(certObj);
                                } else {
                                    throw new BadRequestException("CertChain not provided");
                                }
                            }
                            continue;
                        }
                    }
                }

                if (!generateServerCert && ct.equals("sslserver")) {
                    if (!cdata.getToken().equals("internal")) {
                        cs.putString(csSubsystem + ".cert.sslserver.nickname", cdata.getNickname());
                    } else {
                        cs.putString(csSubsystem + ".cert.sslserver.nickname", data.getToken() +
                                ":" + cdata.getNickname());
                    }
                    cs.putString(csSubsystem + ".sslserver.nickname", cdata.getNickname());
                    cs.putString(csSubsystem + ".sslserver.cert", cdata.getCert());
                    cs.putString(csSubsystem + ".sslserver.certreq", cdata.getRequest());
                    cs.putString(csSubsystem + ".sslserver.tokenname", cdata.getToken());
                    continue;
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

                if (!data.getStepTwo()) {
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
                    CMS.debug("configure(): step two selected.  keys will not be generated for '" + ct + "'");
                }

                String tokenName = cdata.getToken() != null ? cdata.getToken() : token;
                Cert certObj = new Cert(tokenName, nickname, ct);
                certObj.setDN(dn);
                certObj.setSubsystem(cs.getString("preop.cert." + ct + ".subsystem"));
                certObj.setType(cs.getString("preop.cert." + ct + ".type"));

                if (!data.getStepTwo()) {
                    ConfigurationUtils.configCert(null, null, null, certObj, null);
                } else {
                    String subsystem = cs.getString("preop.cert." + ct + ".subsystem");
                    if (data.getStandAlone()) {
                        // Stand-alone PKI (Step 2)
                        certStr = cdata.getCert();
                        certStr = CryptoUtil.stripCertBrackets(certStr.trim());
                        certStr = CryptoUtil.normalizeCertStr(certStr);
                        cs.putString(subsystem + "." + ct + ".cert", certStr);
                    } else {
                        certStr = cs.getString(subsystem + "." + ct + ".cert" );
                    }

                    certObj.setCert(certStr);
                    CMS.debug("Step 2:  certStr for '" + ct + "' is " + certStr);
                }

                // Handle Cert Requests for everything EXCEPT Stand-alone PKI (Step 2)
                if (data.getStandAlone()) {
                    if (!data.getStepTwo()) {
                        // Stand-alone PKI (Step 1)
                        ConfigurationUtils.handleCertRequest(cs, ct, certObj);

                        CMS.debug("Stand-alone " + csType + " Admin CSR");
                        String adminSubjectDN = data.getAdminSubjectDN();
                        String certreqStr = data.getAdminCertRequest();
                        certreqStr = CryptoUtil.normalizeCertAndReq(certreqStr);
                        cs.putString("preop.cert.admin.dn", adminSubjectDN);
                        cs.putString(csSubsystem + ".admin.certreq", certreqStr);
                        cs.putString(csSubsystem + ".admin.cert", "...paste certificate here...");
                    }
                } else {
                    ConfigurationUtils.handleCertRequest(cs, ct, certObj);
                }

                if (data.getIsClone().equals("true")) {
                    ConfigurationUtils.updateCloneConfig();
                }

                // to determine if we have the signing cert when using an external ca
                // this will only execute on a ca or stand-alone pki
                String b64 = cdata.getCert();
                if ((ct.equals("signing") || ct.equals("external_signing")) && (b64!= null) && (b64.length()>0) && (!b64.startsWith("..."))) {
                    hasSigningCert = true;
                    if (data.getIssuingCA().equals("External CA")) {
                        b64 = CryptoUtil.stripCertBrackets(b64.trim());
                        certObj.setCert(CryptoUtil.normalizeCertStr(b64));

                        if (cdata.getCertChain() != null) {
                            certObj.setCertChain(cdata.getCertChain());
                        } else {
                            throw new BadRequestException("CertChain not provided");
                        }
                    }
                }

                certs.addElement(certObj);
            }
            // make sure to commit changes here for step 1
            cs.commit(false);

        } catch (NumberFormatException e) {
            // move these validations to validate()?
            throw new BadRequestException("Non-integer value for key size");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new BadRequestException("Invalid algorithm " + e);
        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException("Error in setting certificate names and key sizes: " + e);
        }

        // non-Stand-alone PKI submitting CSRs to external ca
        if ((data.getIssuingCA()!= null) && data.getIssuingCA().equals("External CA") && (!hasSigningCert)) {
            CMS.debug("Submit CSRs to external ca . . .");
            response.setSystemCerts(SystemCertDataFactory.create(certs));
            response.setStatus(SUCCESS);
            return response;
        }

        Enumeration<Cert> c = certs.elements();
        while (c.hasMoreElements()) {
            Cert cert = c.nextElement();
            int ret;
            try {
                CMS.debug("Processing '" + cert.getCertTag() + "' certificate:");
                ret = ConfigurationUtils.handleCerts(cert);
                ConfigurationUtils.setCertPermissions(cert.getCertTag());
                CMS.debug("Processed '" + cert.getCertTag() + "' certificate.");
            } catch (Exception e) {
                e.printStackTrace();
                throw new PKIException("Error in configuring system certificates" + e);
            }
            if (ret != 0) {
                throw new PKIException("Error in configuring system certificates");
            }
        }
        response.setSystemCerts(SystemCertDataFactory.create(certs));

        // BackupKeyCertPanel/SavePKCS12Panel
        CMS.debug("=== BackupKeyCert Panel/SavePKCS12 Panel ===");
        if (data.getBackupKeys().equals("true")) {
            try {
                ConfigurationUtils.backupKeys(data.getBackupPassword(), data.getBackupFile());
            } catch (Exception e) {
                e.printStackTrace();
                throw new PKIException("Error in creating pkcs12 to backup keys and certs: " + e);
            }
        }

        // AdminPanel
        CMS.debug("=== Admin Panel ===");
        adminPanel(data, response);

        // Done Panel
        // Create or update security domain
        CMS.debug("=== Done Panel ===");
        try {
            if (securityDomainType.equals(ConfigurationRequest.NEW_DOMAIN)) {
                ConfigurationUtils.createSecurityDomain();
            } else {
                ConfigurationUtils.updateSecurityDomain();
            }
            cs.putString("service.securityDomainPort", CMS.getAgentPort());
            cs.putString("securitydomain.store", "ldap");
            cs.commit(false);
        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException("Error while updating security domain: " + e);
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
            if (csType.equals("KRA") && (!data.getStandAlone()) && (!ca_host.equals(""))) {
                ConfigurationUtils.updateConnectorInfo(CMS.getAgentHost(), CMS.getAgentPort());
                ConfigurationUtils.setupClientAuthUser();
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException("Errors in pushing KRA connector information to the CA: " + e);
        }

        // import the CA certificate into the OCSP
        // configure the CRL Publishing to OCSP in CA
        try {
            if (csType.equals("OCSP") && (!ca_host.equals(""))) {
                CMS.reinit(IOCSPAuthority.ID);
                ConfigurationUtils.importCACertToOCSP();
                if (!data.getStandAlone()) {
                    ConfigurationUtils.updateOCSPConfig();
                    ConfigurationUtils.setupClientAuthUser();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException("Errors in configuring CA publishing to OCSP: " + e);
        }

        if (!data.getIsClone().equals("true")) {
            try {
                if (csType.equals("CA") || csType.equals("KRA")) {
                     ConfigurationUtils.updateNextRanges();
                }
            } catch (Exception e) {
                e.printStackTrace();
                throw new PKIException("Errors in updating next serial number ranges in DB: " + e);
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
            throw new PKIException("Errors in determining if security domain host is a master CA");
        }

        try {
            ConfigurationUtils.setupDBUser();
        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException("Errors in creating or updating dbuser: " + e);
        }

        if (csType.equals("TPS")) {
            try {
                ConfigurationUtils.addProfilesToTPSUser(data.getAdminUID());

                URI secdomainURI = new URI(data.getSecurityDomainUri());

                // register TPS with CA
                URI caURI = new URI(data.getCaUri());
                ConfigurationUtils.registerUser(secdomainURI, caURI, "ca");

                // register TPS with TKS
                URI tksURI = new URI(data.getTksUri());
                ConfigurationUtils.registerUser(secdomainURI, tksURI, "tks");

                if (data.getEnableServerSideKeyGen().equalsIgnoreCase("true")) {
                    URI kraURI = new URI(data.getKraUri());
                    ConfigurationUtils.registerUser(secdomainURI, kraURI, "kra");
                    String transportCert = ConfigurationUtils.getTransportCert(secdomainURI, kraURI);
                    ConfigurationUtils.exportTransportCert(secdomainURI, tksURI, transportCert);
                }

                // generate shared secret from the tks
                ConfigurationUtils.getSharedSecret(
                        tksURI.getHost(),
                        tksURI.getPort(),
                        Boolean.getBoolean(data.getImportSharedSecret()));

            } catch (URISyntaxException e) {
                throw new BadRequestException("Invalid URI for CA, TKS or KRA");
            } catch (Exception e) {
                e.printStackTrace();
                throw new PKIException("Errors in registering TPS to CA, TKS or KRA: " + e);
            }
        }

        cs.putInteger("cs.state", 1);

        // update serial numbers for clones

        // save some variables, remove remaining preops
        try {
            ConfigurationUtils.removePreopConfigEntries();
        } catch (EBaseException e) {
            e.printStackTrace();
            throw new PKIException("Errors when removing preop config entries: " + e);
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

    private void caInfoPanel(ConfigurationRequest data, String subsystemNick) {
        URI caUri = null;
        try {
            caUri = new URI(data.getCaUri());
        } catch (URISyntaxException e) {
            throw new BadRequestException("Invalid caURI " + caUri);
        }
        ConfigurationUtils.updateCAConnInfo(caUri, subsystemNick);
    }

    private void tksInfoPanel(ConfigurationRequest data, String subsystemNick) {
        URI tksUri = null;
        try {
            tksUri = new URI(data.getTksUri());
        } catch (URISyntaxException e) {
            throw new BadRequestException("Invalid tksURI " + tksUri);
        }

        ConfigurationUtils.updateTKSConnInfo(tksUri, subsystemNick);
    }

    private void kraInfoPanel(ConfigurationRequest data, String subsystemNick) {
        URI kraUri = null;
        try {
            kraUri = new URI(data.getCaUri());
        } catch (URISyntaxException e) {
            throw new BadRequestException("Invalid kraURI " + kraUri);
        }
        boolean keyGen = data.getEnableServerSideKeyGen().equalsIgnoreCase("true");
        ConfigurationUtils.updateKRAConnInfo(keyGen, kraUri, subsystemNick);
    }

    private void adminPanel(ConfigurationRequest data, ConfigurationResponse response) {
        if (!data.getIsClone().equals("true")) {
            try {
                X509CertImpl admincerts[] = new X509CertImpl[1];
                ConfigurationUtils.createAdmin(data.getAdminUID(), data.getAdminEmail(),
                        data.getAdminName(), data.getAdminPassword());
                if (data.getImportAdminCert().equalsIgnoreCase("true")) {
                    String b64 = CryptoUtil.stripCertBrackets(data.getAdminCert().trim());
                    if (data.getStandAlone() && data.getStepTwo()) {
                        // Stand-alone PKI (Step 2)
                        CMS.debug("adminPanel:  Stand-alone " + csType + " Admin Cert");
                        cs.putString(csSubsystem + ".admin.cert", b64);
                        cs.commit(false);
                    }
                    // Convert Admin Cert to X509CertImpl
                    byte[] b = CryptoUtil.base64Decode(b64);
                    admincerts[0] = new X509CertImpl(b);
                } else {
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
                }
                CMS.reinit(IUGSubsystem.ID);

                IUGSubsystem ug = (IUGSubsystem) CMS.getSubsystem(IUGSubsystem.ID);
                IUser user = ug.getUser(data.getAdminUID());
                user.setX509Certificates(admincerts);
                ug.addUserCert(user);
                response.setAdminCert(admincerts[0]);

            } catch (Exception e) {
                e.printStackTrace();
                throw new PKIException("Error in creating admin user: " + e);
            }
        }
    }

    private void databasePanel(ConfigurationRequest data) {
        cs.putString("internaldb.ldapconn.host", data.getDsHost());
        cs.putString("internaldb.ldapconn.port", data.getDsPort());
        cs.putString("internaldb.database", data.getDatabase());
        cs.putString("internaldb.basedn", data.getBaseDN());
        cs.putString("internaldb.ldapauth.bindDN", data.getBindDN());
        cs.putString("internaldb.ldapconn.secureConn", (data.getSecureConn().equals("on") ? "true" : "false"));
        cs.putString("preop.database.removeData", data.getRemoveData());

        if (csType.equals("TPS")) {
            cs.putString("tokendb.activityBaseDN", "ou=Activities," + data.getBaseDN());
            cs.putString("tokendb.baseDN", "ou=Tokens," + data.getBaseDN());
            cs.putString("tokendb.certBaseDN", "ou=Certificates," + data.getBaseDN());
            cs.putString("tokendb.userBaseDN", data.getBaseDN());
            cs.putString("tokendb.hostport", data.getDsHost() + ":" + data.getDsPort());
        }

        try {
            cs.commit(false);
        } catch (EBaseException e2) {
            e2.printStackTrace();
            throw new PKIException("Unable to commit config parameters to file");
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
                throw new BadRequestException("Master and clone must not share the same internal database");
            }

            if (!masterbasedn.equals(data.getBaseDN())) {
                throw new BadRequestException("Master and clone should have the same base DN");
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

            cs.putString("preop.internaldb.replicateSchema", data.getReplicateSchema());
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

            if (!data.getStepTwo()) {
                ConfigurationUtils.populateDB();

                cs.putString("preop.internaldb.replicationpwd", replicationpwd);
                cs.putString("preop.database.removeData", "false");
                cs.commit(false);

                if (data.getIsClone().equals("true")) {
                    CMS.debug("Start setting up replication.");
                    ConfigurationUtils.setupReplication();
                }

                ConfigurationUtils.reInitSubsystem(csType);
                ConfigurationUtils.populateDBManager();
                ConfigurationUtils.populateVLVIndexes();
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException("Error in populating database: " + e, e);
        }
    }

    private void hierarchyPanel(ConfigurationRequest data) {
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
                throw new BadRequestException("Invalid hierarchy provided");
            }
        }
    }

    private void getCloningData(ConfigurationRequest data, String certList, String token, String domainXML) {
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
            throw new PKIException("Error in determining whether clone URI is valid");
        }

        if (!validCloneUri) {
            throw new BadRequestException(
                    "Invalid clone URI provided.  Does not match the available subsystems in the security domain");
        }

        if (csType.equals("CA")) {
            try {
                int masterAdminPort = ConfigurationUtils.getPortFromSecurityDomain(domainXML,
                        masterHost, masterPort, "CA", "SecurePort", "SecureAdminPort");
                ConfigurationUtils.importCertChain(masterHost, masterAdminPort, "/ca/admin/ca/getCertChain",
                        "clone");
            } catch (Exception e) {
                e.printStackTrace();
                throw new PKIException("Failed to import certificate chain from master" + e);
            }
        }

        try {
            ConfigurationUtils.getConfigEntriesFromMaster();
        } catch (Exception e) {
            e.printStackTrace();
            throw new PKIException("Failed to obtain configuration entries from the master for cloning " + e);
        }

        // restore certs from P12 file
        if (token.equals(ConfigurationRequest.TOKEN_DEFAULT)) {
            String p12File = data.getP12File();
            String p12Pass = data.getP12Password();
            try {
                ConfigurationUtils.restoreCertsFromP12(p12File, p12Pass);
            } catch (Exception e) {
                e.printStackTrace();
                throw new PKIException("Failed to restore certificates from p12 file" + e);
            }
        }

        boolean cloneReady = ConfigurationUtils.isCertdbCloned();
        if (!cloneReady) {
            CMS.debug("clone does not have all the certificates.");
            throw new PKIException("Clone does not have all the required certificates");
        }
    }

    private String securityDomainPanel(ConfigurationRequest data, String securityDomainType) {
        String domainXML = null;
        String securityDomainName = data.getSecurityDomainName();
        String securityDomainURL = data.getSecurityDomainUri();

        if (securityDomainType.equals(ConfigurationRequest.NEW_DOMAIN)) {
            cs.putString("preop.securitydomain.select", "new");
            cs.putString("securitydomain.select", "new");
            cs.putString("preop.securitydomain.name", securityDomainName);
            cs.putString("securitydomain.name", securityDomainName);
            cs.putString("securitydomain.host", CMS.getEENonSSLHost());
            cs.putString("securitydomain.httpport", CMS.getEENonSSLPort());
            cs.putString("securitydomain.httpsagentport", CMS.getAgentPort());
            cs.putString("securitydomain.httpseeport", CMS.getEESSLPort());
            cs.putString("securitydomain.httpsadminport", CMS.getAdminPort());
            // Stand-alone PKI (Step 1)
            if (data.getStandAlone()) {
                cs.putString("preop.cert.subsystem.type", "remote");
            } else {
                cs.putString("preop.cert.subsystem.type", "local");
            }
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
                throw new PKIException("Failed to import certificate chain from security domain master: " + e);
            }

            // log onto security domain and get token
            String user = data.getSecurityDomainUser();
            String pass = data.getSecurityDomainPassword();
            String installToken;
            try {
                installToken = ConfigurationUtils.getInstallToken(host, port, user, pass);
            } catch (Exception e) {
                e.printStackTrace();
                throw new PKIException("Failed to obtain installation token from security domain: " + e);
            }

            if (installToken == null) {
                throw new PKIException("Failed to obtain installation token from security domain");
            }
            CMS.setConfigSDSessionId(installToken);

            try {
                domainXML = ConfigurationUtils.getDomainXML(host, port, true);
                ConfigurationUtils.getSecurityDomainPorts(domainXML, host, port);
            } catch (Exception e) {
                e.printStackTrace();
                throw new PKIException("Failed to obtain security domain decriptor from security domain master: " + e);
            }
        }
        return domainXML;
    }

    private void tokenPanel(ConfigurationRequest data, String token) {
        cs.putString("preop.module.token", token);

        if (! token.equals(ConfigurationRequest.TOKEN_DEFAULT)) {
            try {
                CryptoManager cryptoManager = CryptoManager.getInstance();
                CryptoToken ctoken = cryptoManager.getTokenByName(token);
                String tokenpwd = data.getTokenPassword();
                ConfigurationUtils.loginToken(ctoken, tokenpwd);
            } catch (NotInitializedException e) {
                throw new PKIException("Token is not initialized");
            } catch (NoSuchTokenException e) {
                throw new BadRequestException("Invalid Token provided. No such token.");
            } catch (TokenException e) {
                e.printStackTrace();
                throw new PKIException("Token Exception" + e);
            } catch (IncorrectPasswordException e) {
                throw new BadRequestException("Incorrect Password provided for token.");
            }
        }
    }

    private void validateData(ConfigurationRequest data) {
        // get required info from CS.cfg
        String preopPin;
        try {
            preopPin = cs.getString("preop.pin");
        } catch (Exception e) {
            CMS.debug("validateData: Failed to get required config form CS.cfg");
            e.printStackTrace();
            throw new PKIException("Unable to retrieve required configuration from configuration files");
        }

        // get the preop pin and validate it
        String pin = data.getPin();
        if (pin == null) {
            throw new BadRequestException("No preop pin provided");
        }
        if (!preopPin.equals(pin)) {
            throw new BadRequestException("Incorrect pin provided");
        }

        // validate legal stand-alone PKI subsystems
        if (data.getStandAlone()) {
            // ADD checks for valid types of Stand-alone PKI subsystems here
            // AND to the 'checkStandalonePKI()' Python method of
            // the 'ConfigurationFile' Python class in the Python file called
            // 'pkihelper.py'
            if (!csType.equals("KRA")) {
                throw new BadRequestException("Stand-alone PKI " + csType + " subsystems are currently NOT supported!");
            }
            if ((data.getIsClone() != null) && (data.getIsClone().equals("true"))) {
                throw new BadRequestException("A stand-alone PKI subsystem cannot be a clone");
            }
        }

        // validate security domain settings
        String domainType = data.getSecurityDomainType();
        if (domainType == null) {
            throw new BadRequestException("Security Domain Type not provided");
        }

        if (domainType.equals(ConfigurationRequest.NEW_DOMAIN)) {
            if (!(data.getStandAlone() || csType.equals("CA"))) {
                throw new BadRequestException("New Domain is only valid for stand-alone PKI or CA subsytems");
            }
            if (data.getSecurityDomainName() == null) {
                throw new BadRequestException("Security Domain Name is not provided");
            }
        } else if (domainType.equals(ConfigurationRequest.EXISTING_DOMAIN)) {
            if (data.getStandAlone()) {
                throw new BadRequestException("Existing security domains are not valid for stand-alone PKI subsytems");
            }

            String domainURI = data.getSecurityDomainUri();
            if (domainURI == null) {
                throw new BadRequestException("Existing security domain requested, but no security domain URI provided");
            }

            try {
                @SuppressWarnings("unused")
                URL admin_u = new URL(domainURI);  // check for invalid URL
            } catch (MalformedURLException e) {
                throw new BadRequestException("Invalid security domain URI");
            }
            if ((data.getSecurityDomainUser() == null) || (data.getSecurityDomainPassword() == null)) {
                throw new BadRequestException("Security domain user or password not provided");
            }

        } else {
            throw new BadRequestException("Invalid security domain URI provided");
        }

        if ((data.getSubsystemName() == null) || (data.getSubsystemName().length() ==0)) {
            throw new BadRequestException("Invalid or no subsystem name provided");
        }

        if ((data.getIsClone() != null) && (data.getIsClone().equals("true"))) {
            String cloneUri = data.getCloneUri();
            if (cloneUri == null) {
                throw new BadRequestException("Clone selected, but no clone URI provided");
            }
            try {
                @SuppressWarnings("unused")
                URL url = new URL(cloneUri); // check for invalid URL
                // confirm protocol is https
            } catch (MalformedURLException e) {
                throw new BadRequestException("Invalid clone URI");
            }

            if (data.getToken().equals(ConfigurationRequest.TOKEN_DEFAULT)) {
                if (data.getP12File() == null) {
                    throw new BadRequestException("P12 filename not provided");
                }

                if (data.getP12Password() == null) {
                    throw new BadRequestException("P12 password not provided");
                }
            }
        } else {
            data.setIsClone("false");
        }

        String dsHost = data.getDsHost();
        if (dsHost == null || dsHost.length() == 0) {
            throw new BadRequestException("Internal database host not provided");
        }

        try {
            Integer.parseInt(data.getDsPort());  // check for errors
        } catch (NumberFormatException e) {
            throw new BadRequestException("Internal database port is invalid");
        }

        String basedn = data.getBaseDN();
        if (basedn == null || basedn.length() == 0) {
            throw new BadRequestException("Internal database basedn not provided");
        }

        String binddn = data.getBindDN();
        if (binddn == null || binddn.length() == 0) {
            throw new BadRequestException("Internal database basedn not provided");
        }

        String database = data.getDatabase();
        if (database == null || database.length() == 0) {
            throw new BadRequestException("Internal database database name not provided");
        }

        String bindpwd = data.getBindpwd();
        if (bindpwd == null || bindpwd.length() == 0) {
            throw new BadRequestException("Internal database database name not provided");
        }

        String masterReplicationPort = data.getMasterReplicationPort();
        if (masterReplicationPort != null && masterReplicationPort.length() > 0) {
            try {
                Integer.parseInt(masterReplicationPort); // check for errors
            } catch (NumberFormatException e) {
                throw new BadRequestException("Master replication port is invalid");
            }
        }

        String cloneReplicationPort = data.getCloneReplicationPort();
        if (cloneReplicationPort != null && cloneReplicationPort.length() > 0) {
            try {
                Integer.parseInt(cloneReplicationPort); // check for errors
            } catch (Exception e) {
                throw new BadRequestException("Clone replication port is invalid");
            }
        }

        if ((data.getReplicateSchema() != null) && (data.getReplicateSchema().equalsIgnoreCase("false"))) {
            data.setReplicateSchema("false");
        } else {
            data.setReplicateSchema("true");
        }

        if ((data.getBackupKeys() != null) && data.getBackupKeys().equals("true")) {
            if ((data.getBackupFile() == null) || (data.getBackupFile().length()<=0)) {
                //TODO: also check for valid path, perhaps by touching file there
                throw new BadRequestException("Invalid key backup file name");
            }

            if ((data.getBackupPassword() == null) || (data.getBackupPassword().length()<8)) {
                throw new BadRequestException("key backup password must be at least 8 characters");
            }
        } else {
            data.setBackupKeys("false");
        }

        if (csType.equals("CA") && (data.getHierarchy() == null)) {
            throw new BadRequestException("Hierarchy is required for CA, not provided");
        }

        if (data.getIsClone().equals("false")) {
            if ((data.getAdminUID() == null) || (data.getAdminUID().length() == 0)) {
                throw new BadRequestException("Admin UID not provided");
            }
            if ((data.getAdminPassword() == null) || (data.getAdminPassword().length() == 0)) {
                throw new BadRequestException("Admin Password not provided");
            }
            if ((data.getAdminEmail() == null) || (data.getAdminEmail().length() == 0)) {
                throw new BadRequestException("Admin UID not provided");
            }
            if ((data.getAdminName() == null) || (data.getAdminName().length() == 0)) {
                throw new BadRequestException("Admin name not provided");
            }

            if (data.getImportAdminCert() == null) {
                data.setImportAdminCert("false");
            }

            if (data.getImportAdminCert().equalsIgnoreCase("true")) {
                if (data.getAdminCert() == null) {
                    throw new BadRequestException("Admin Cert not provided");
                }
            } else {
                if ((data.getAdminCertRequest() == null) || (data.getAdminCertRequest().length() == 0)) {
                    throw new BadRequestException("Admin cert request not provided");
                }
                if ((data.getAdminCertRequestType() == null) || (data.getAdminCertRequestType().length() == 0)) {
                    throw new BadRequestException("Admin cert request type not provided");
                }
                if ((data.getAdminSubjectDN() == null) || (data.getAdminSubjectDN().length() == 0)) {
                    throw new BadRequestException("Admin subjectDN not provided");
                }
            }
        }

        if (data.getGenerateServerCert() == null) {
            data.setGenerateServerCert("true");
        }

        if (csType.equals("TPS")) {
            if ((data.getCaUri() == null) || data.getCaUri().isEmpty()) {
                throw new BadRequestException("CA URI not provided");
            }
            try {
                @SuppressWarnings("unused")
                URI ca_uri = new URI(data.getCaUri());
            } catch (URISyntaxException e) {
                throw new BadRequestException("Invalid CA URI");
            }

            if ((data.getTksUri() == null) || data.getTksUri().isEmpty()) {
                throw new BadRequestException("TKS URI not provided");
            }
            try {
                @SuppressWarnings("unused")
                URI tks_uri = new URI(data.getTksUri());
            } catch (URISyntaxException e) {
                throw new BadRequestException("Invalid TKS URI");
            }

            if (data.getEnableServerSideKeyGen().equalsIgnoreCase("true")) {
                if ((data.getKraUri() == null) || data.getKraUri().isEmpty()) {
                    throw new BadRequestException("KRA URI required if server-side key generation requested");
                }
                try {
                    @SuppressWarnings("unused")
                    URI kra_uri = new URI(data.getKraUri());
                } catch (URISyntaxException e) {
                    throw new BadRequestException("Invalid KRA URI");
                }
            }

            if ((data.getAuthdbBaseDN()==null) || data.getAuthdbBaseDN().isEmpty()) {
                throw new BadRequestException("Authentication Database baseDN not provided");
            }
            if ((data.getAuthdbHost()==null) || data.getAuthdbHost().isEmpty()) {
                throw new BadRequestException("Authentication Database hostname not provided");
            }
            if ((data.getAuthdbPort()==null) || data.getAuthdbPort().isEmpty()) {
                throw new BadRequestException("Authentication Database port not provided");
            }
            if ((data.getAuthdbSecureConn()==null) || data.getAuthdbSecureConn().isEmpty()) {
                throw new BadRequestException("Authentication Database secure conn not provided");
            }

            try {
                Integer.parseInt(data.getAuthdbPort()); // check for errors
            } catch (NumberFormatException e) {
                throw new BadRequestException("Authdb port is invalid");
            }

            // TODO check connection with authdb

            if (data.getImportSharedSecret().equalsIgnoreCase("true")) {
                data.setImportSharedSecret("true");
            } else {
                data.setImportSharedSecret("false");
            }
        }
    }
}
