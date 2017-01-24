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
package org.dogtagpki.server.rest;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.UriInfo;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.mutable.MutableBoolean;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.util.IncorrectPasswordException;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.system.ConfigurationRequest;
import com.netscape.certsrv.system.ConfigurationResponse;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.certsrv.system.SystemConfigResource;
import com.netscape.certsrv.usrgrp.IUGSubsystem;
import com.netscape.certsrv.usrgrp.IUser;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.csadmin.Cert;
import com.netscape.cms.servlet.csadmin.ConfigurationUtils;
import com.netscape.cms.servlet.csadmin.SystemCertDataFactory;
import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.cmsutil.util.Utils;

import netscape.security.x509.X509CertImpl;

/**
 * @author alee
 *
 */
public class SystemConfigService extends PKIService implements SystemConfigResource {
    @Context
    public UriInfo uriInfo;

    @Context
    public HttpHeaders headers;

    @Context
    public Request request;

    @Context
    public HttpServletRequest servletRequest;

    public IConfigStore cs;
    public String csType;
    public String csSubsystem;
    public String csState;
    public boolean isMasterCA = false;
    public String instanceRoot;

    public static String SUCCESS = "0";
    public static final String RESTART_SERVER_AFTER_CONFIGURATION =
            "restart_server_after_configuration";

    public SystemConfigService() throws EBaseException {
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
     * @see com.netscape.cms.servlet.csadmin.SystemConfigurationResource#configure(com.netscape.cms.servlet.csadmin.data.ConfigurationData)
     */
    @Override
    public ConfigurationResponse configure(ConfigurationRequest request) throws Exception {

        CMS.debug("SystemConfigService: configure()");

        try {
            ConfigurationResponse response = new ConfigurationResponse();
            configure(request, response);
            return response;

        } catch (PKIException e) { // normal responses
            CMS.debug(e.getMessage()); // log the response
            throw e;

        } catch (Exception e) { // unexpected exceptions
            CMS.debug(e); // show stack trace for troubleshooting
            throw e;

        } catch (Error e) { // system errors
            CMS.debug(e); // show stack trace for troubleshooting
            throw e;
        }
    }

    public void configure(ConfigurationRequest data, ConfigurationResponse response) throws Exception {


        if (csState.equals("1")) {
            throw new BadRequestException("System is already configured");
        }

        CMS.debug("SystemConfigService: request: " + data);
        validateRequest(data);

        Collection<String> certList = getCertList(data);

        // specify module and log into token
        CMS.debug("=== Token Authentication ===");
        String token = data.getToken();
        if (CryptoUtil.isInternalToken(token)) {
            token = CryptoUtil.INTERNAL_TOKEN_FULL_NAME;
        }
        loginToken(data, token);

        // configure security domain
        CMS.debug("=== Security Domain Configuration ===");
        String domainXML = configureSecurityDomain(data);

        // configure subsystem
        CMS.debug("=== Subsystem Configuration ===");
        configureSubsystem(data, certList, token, domainXML);

        // configure hierarchy
        CMS.debug("=== Hierarchy Configuration ===");
        configureHierarchy(data);

        // configure database
        CMS.debug("=== Database Configuration ===");
        try {
            configureDatabase(data);
            cs.commit(false);
        } catch (EBaseException e) {
            CMS.debug(e);
            throw new PKIException("Unable to commit config parameters to file", e);
        }
        initializeDatabase(data);

        ConfigurationUtils.reInitSubsystem(csType);

        configureCACertChain(data, domainXML);

        Collection<Cert> certs = new ArrayList<Cert>();
        MutableBoolean hasSigningCert = new MutableBoolean();
        processCerts(data, token, certList, certs, hasSigningCert);

        // non-Stand-alone PKI submitting CSRs to external ca
        if (data.getIssuingCA() != null && data.getIssuingCA().equals("External CA") && !hasSigningCert.booleanValue()) {
            CMS.debug("Submit CSRs to external ca . . .");
            response.setSystemCerts(SystemCertDataFactory.create(certs));
            response.setStatus(SUCCESS);
            return;
        }

        for (Cert cert : certs) {
            try {
                CMS.debug("Processing '" + cert.getCertTag() + "' certificate:");
                ConfigurationUtils.handleCerts(cert);
                ConfigurationUtils.setCertPermissions(cert.getCertTag());
                CMS.debug("Processed '" + cert.getCertTag() + "' certificate.");
            } catch (Exception e) {
                CMS.debug(e);
                throw new PKIException("Error in configuring system certificates: " + e, e);
            }
        }
        response.setSystemCerts(SystemCertDataFactory.create(certs));

        // backup keys
        CMS.debug("=== Backup Keys ===");
        if (data.getBackupKeys().equals("true")) {
            backupKeys(data);
        }

        // configure admin
        CMS.debug("=== Admin Configuration ===");
        configureAdministrator(data, response);

        // create or update security domain
        CMS.debug("=== Finalization ===");
        setupSecurityDomain(data);
        setupDBUser(data);
        finalizeConfiguration(data);

        cs.putInteger("cs.state", 1);

        // update serial numbers for clones

        // save some variables, remove remaining preops
        try {
            ConfigurationUtils.removePreopConfigEntries();
        } catch (EBaseException e) {
            CMS.debug(e);
            throw new PKIException("Errors when removing preop config entries: " + e, e);
        }

        // Create an empty file that designates the fact that although
        // this server instance has been configured, it has NOT yet
        // been restarted!
        String restart_server = instanceRoot + "/conf/" + RESTART_SERVER_AFTER_CONFIGURATION;
        Utils.exec("touch " + restart_server);
        Utils.exec("chmod 00660 " + restart_server);

        response.setStatus(SUCCESS);
    }

    private void setupDBUser(ConfigurationRequest data) {
        try {
            if (!data.getSharedDB()) ConfigurationUtils.setupDBUser();
        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Errors in creating or updating dbuser: " + e);
        }
    }

    private void setupSecurityDomain(ConfigurationRequest data) {
        try {
            String securityDomainType = data.getSecurityDomainType();
            if (securityDomainType.equals(ConfigurationRequest.NEW_DOMAIN)) {
                CMS.debug("Creating new security domain");
                ConfigurationUtils.createSecurityDomain();
            } else if (securityDomainType.equals(ConfigurationRequest.NEW_SUBDOMAIN)) {
                CMS.debug("Creating subordinate CA security domain");

                // switch out security domain parameters from issuing CA security domain
                // to subordinate CA hosted security domain
                cs.putString("securitydomain.name", data.getSubordinateSecurityDomainName());
                cs.putString("securitydomain.host", CMS.getEENonSSLHost());
                cs.putString("securitydomain.httpport", CMS.getEENonSSLPort());
                cs.putString("securitydomain.httpsagentport", CMS.getAgentPort());
                cs.putString("securitydomain.httpseeport", CMS.getEESSLPort());
                cs.putString("securitydomain.httpsadminport", CMS.getAdminPort());
                ConfigurationUtils.createSecurityDomain();
            } else {
                CMS.debug("Updating existing security domain");
                ConfigurationUtils.updateSecurityDomain();
            }
            cs.putString("service.securityDomainPort", CMS.getAgentPort());
            cs.putString("securitydomain.store", "ldap");
            cs.commit(false);
        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Error while updating security domain: " + e);
        }
    }

    public Collection<String> getCertList(ConfigurationRequest request) {

        Collection<String> certList = new ArrayList<String>();

        if (request.getStandAlone() && request.getStepTwo()) {
            // Stand-alone PKI (Step 2)
            // Special case to import the external CA and its Chain
            certList.add("external_signing");
        }

        try {
            String value = cs.getString("preop.cert.list");
            certList.addAll(Arrays.asList(value.split(",")));

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Unable to get certList from config file");
        }

        return certList;
    }

    public void processCerts(ConfigurationRequest request, String token, Collection<String> certList,
            Collection<Cert> certs, MutableBoolean hasSigningCert) {

        try {
            boolean generateServerCert = !request.getGenerateServerCert().equalsIgnoreCase("false");
            boolean generateSubsystemCert = request.getGenerateSubsystemCert();

            hasSigningCert.setValue(false);

            for (String tag : certList) {
                boolean enable = cs.getBoolean("preop.cert." + tag + ".enable", true);
                if (!enable) continue;

                SystemCertData certData = null;

                for (SystemCertData systemCert : request.getSystemCerts()) {
                    if (systemCert.getTag().equals(tag)) {
                        certData = systemCert;
                        break;
                    }
                }

                if (certData == null) {
                    CMS.debug("No data for '" + tag + "' was found!");
                    throw new BadRequestException("No data for '" + tag + "' was found!");
                }

                String tokenName = certData.getToken() != null ? certData.getToken() : token;
                if (request.getStandAlone() && request.getStepTwo()) {
                    // Stand-alone PKI (Step 2)
                    if (tag.equals("external_signing")) {

                        String b64 = certData.getCert();
                        if (b64 != null && b64.length() > 0 && !b64.startsWith("...")) {
                            hasSigningCert.setValue(true);

                            if (request.getIssuingCA().equals("External CA")) {
                                String nickname = certData.getNickname() != null ? certData.getNickname() : "caSigningCert External CA";
                                Cert cert = new Cert(tokenName, nickname, tag);
                                ConfigurationUtils.setExternalCACert(b64, csSubsystem, cs, cert);

                                CMS.debug("Step 2:  certStr for '" + tag + "' is " + b64);
                                String certChainStr = certData.getCertChain();

                                if (certChainStr != null) {
                                    ConfigurationUtils.setExternalCACertChain(certChainStr, csSubsystem, cs, cert);
                                    CMS.debug("Step 2:  certChainStr for '" + tag + "' is " + certChainStr);
                                    certs.add(cert);

                                } else {
                                    throw new BadRequestException("CertChain not provided");
                                }
                            }

                            continue;
                        }
                    }
                }

                if (!generateServerCert && tag.equals("sslserver")) {
                    updateConfiguration(request, certData, "sslserver");
                    continue;
                }

                if (!generateSubsystemCert && tag.equals("subsystem")) {
                    // update the details for the shared subsystem cert here.
                    updateConfiguration(request, certData, "subsystem");

                    // get parameters needed for cloning
                    updateCloneConfiguration(certData, "subsystem", tokenName);
                    continue;
                }

                processCert(
                        request,
                        token,
                        certList,
                        certs,
                        hasSigningCert,
                        certData,
                        tokenName);
            }

            // make sure to commit changes here for step 1
            cs.commit(false);

        } catch (NumberFormatException e) {
            // move these validations to validate()?
            throw new BadRequestException("Non-integer value for key size");

        } catch (NoSuchAlgorithmException e) {
            throw new BadRequestException("Invalid algorithm " + e);

        } catch (PKIException e) {
            throw e;

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Error in setting certificate names and key sizes: " + e);
        }
    }

    public void processCert(
            ConfigurationRequest request,
            String token,
            Collection<String> certList,
            Collection<Cert> certs,
            MutableBoolean hasSigningCert,
            SystemCertData certData,
            String tokenName) throws Exception {

        String tag = certData.getTag();
        String keytype = certData.getKeyType() != null ? certData.getKeyType() : "rsa";

        String keyalgorithm = certData.getKeyAlgorithm();
        if (keyalgorithm == null) {
            keyalgorithm = keytype.equals("ecc") ? "SHA256withEC" : "SHA256withRSA";
        }

        String signingalgorithm = certData.getSigningAlgorithm() != null ? certData.getSigningAlgorithm() : keyalgorithm;
        String nickname = cs.getString("preop.cert." + tag + ".nickname");
        String dn = cs.getString("preop.cert." + tag + ".dn");

        cs.putString("preop.cert." + tag + ".keytype", keytype);
        cs.putString("preop.cert." + tag + ".keyalgorithm", keyalgorithm);
        cs.putString("preop.cert." + tag + ".signingalgorithm", signingalgorithm);

        // support injecting SAN into server cert
        if ( tag.equals("sslserver") && certData.getServerCertSAN() != null) {
            CMS.debug("updateConfiguration(): san_server_cert found");
            cs.putString("service.injectSAN", "true");
            cs.putString("service.sslserver.san", certData.getServerCertSAN());
        } else {
            if ( tag.equals("sslserver"))
                CMS.debug("SystemConfigService:processCerts(): san_server_cert not found for tag sslserver");
        }
        cs.commit(false);

        if (request.isExternal() && tag.equals("signing")) { // external/existing CA
            // load key pair for existing and externally-signed signing cert
            CMS.debug("SystemConfigService: loading signing cert key pair");
            KeyPair pair = ConfigurationUtils.loadKeyPair(certData.getNickname(), certData.getToken());
            ConfigurationUtils.storeKeyPair(cs, tag, pair);

        } else if (!request.getStepTwo()) {
            if (keytype.equals("ecc")) {
                String curvename = certData.getKeySize() != null ?
                        certData.getKeySize() : cs.getString("keys.ecc.curve.default");
                cs.putString("preop.cert." + tag + ".curvename.name", curvename);
                ConfigurationUtils.createECCKeyPair(token, curvename, cs, tag);

            } else {
                String keysize = certData.getKeySize() != null ? certData.getKeySize() : cs
                        .getString("keys.rsa.keysize.default");
                cs.putString("preop.cert." + tag + ".keysize.size", keysize);
                ConfigurationUtils.createRSAKeyPair(token, Integer.parseInt(keysize), cs, tag);
            }

        } else {
            CMS.debug("configure(): step two selected.  keys will not be generated for '" + tag + "'");
        }

        Cert cert = new Cert(tokenName, nickname, tag);
        cert.setDN(dn);
        cert.setSubsystem(cs.getString("preop.cert." + tag + ".subsystem"));
        cert.setType(cs.getString("preop.cert." + tag + ".type"));

        if (request.isExternal() && tag.equals("signing")) { // external/existing CA

            // update configuration for existing or externally-signed signing certificate
            String certStr = cs.getString("ca." + tag + ".cert" );
            cert.setCert(certStr);
            CMS.debug("SystemConfigService: certificate " + tag + ": " + certStr);
            ConfigurationUtils.updateConfig(cs, tag);

        } else if (!request.getStepTwo()) {
            ConfigurationUtils.configCert(null, null, null, cert);

        } else {
            String subsystem = cs.getString("preop.cert." + tag + ".subsystem");
            String certStr;

            if (request.getStandAlone()) {
                // Stand-alone PKI (Step 2)
                certStr = certData.getCert();
                certStr = CryptoUtil.stripCertBrackets(certStr.trim());
                certStr = CryptoUtil.normalizeCertStr(certStr);
                cs.putString(subsystem + "." + tag + ".cert", certStr);

            } else {
                certStr = cs.getString(subsystem + "." + tag + ".cert" );
            }

            cert.setCert(certStr);
            CMS.debug("Step 2:  certStr for '" + tag + "' is " + certStr);
        }

        if (request.isExternal() && tag.equals("signing")) { // external/existing CA

            CMS.debug("SystemConfigService: Loading cert request for " + tag + " cert");
            ConfigurationUtils.loadCertRequest(cs, tag, cert);

            CMS.debug("SystemConfigService: Loading cert " + tag);
            ConfigurationUtils.loadCert(cs, cert);

        } else if (request.getStandAlone()) {
            // Handle Cert Requests for everything EXCEPT Stand-alone PKI (Step 2)
            if (!request.getStepTwo()) {
                // Stand-alone PKI (Step 1)
                ConfigurationUtils.generateCertRequest(cs, tag, cert);

                CMS.debug("Stand-alone " + csType + " Admin CSR");
                String adminSubjectDN = request.getAdminSubjectDN();
                String certreqStr = request.getAdminCertRequest();
                certreqStr = CryptoUtil.normalizeCertAndReq(certreqStr);

                cs.putString("preop.cert.admin.dn", adminSubjectDN);
                cs.putString(csSubsystem + ".admin.certreq", certreqStr);
                cs.putString(csSubsystem + ".admin.cert", "...paste certificate here...");
            }

        } else {
            ConfigurationUtils.generateCertRequest(cs, tag, cert);
        }

        if (request.isClone()) {
            ConfigurationUtils.updateCloneConfig();
        }

        if (request.isExternal() && tag.equals("signing")) { // external/existing CA
            CMS.debug("SystemConfigService: External CA has signing cert");
            hasSigningCert.setValue(true);
            certs.add(cert);
            return;
        }

        // to determine if we have the signing cert when using an external ca
        // this will only execute on a ca or stand-alone pki
        String b64 = certData.getCert();
        if ((tag.equals("signing") || tag.equals("external_signing")) && b64 != null && b64.length() > 0 && !b64.startsWith("...")) {
            hasSigningCert.setValue(true);

            if (request.getIssuingCA().equals("External CA")) {
                b64 = CryptoUtil.stripCertBrackets(b64.trim());
                cert.setCert(CryptoUtil.normalizeCertStr(b64));

                if (certData.getCertChain() != null) {
                    cert.setCertChain(certData.getCertChain());

                } else {
                    throw new BadRequestException("CertChain not provided");
                }
            }
        }

        certs.add(cert);
    }

    private void updateCloneConfiguration(SystemCertData cdata, String tag, String tokenName) throws NotInitializedException,
            ObjectNotFoundException, TokenException {
        // TODO - some of these parameters may only be valid for RSA
        CryptoManager cryptoManager = CryptoManager.getInstance();
        String nickname;
        if (!CryptoUtil.isInternalToken(tokenName)) {
            CMS.debug("SystemConfigService:updateCloneConfiguration: tokenName=" + tokenName);
            nickname = tokenName + ":" + cdata.getNickname();
        } else {
            CMS.debug("SystemConfigService:updateCloneConfiguration: tokenName empty; using internal");
            nickname = cdata.getNickname();
        }

        X509Certificate cert = cryptoManager.findCertByNickname(nickname);
        PublicKey pubk = cert.getPublicKey();
        byte[] exponent = CryptoUtil.getPublicExponent(pubk);
        byte[] modulus = CryptoUtil.getModulus(pubk);
        PrivateKey privk = cryptoManager.findPrivKeyByCert(cert);

        cs.putString("preop.cert." + tag + ".pubkey.modulus", CryptoUtil.byte2string(modulus));
        cs.putString("preop.cert." + tag + ".pubkey.exponent", CryptoUtil.byte2string(exponent));
        cs.putString("preop.cert." + tag + ".privkey.id", CryptoUtil.byte2string(privk.getUniqueID()));
        cs.putString("preop.cert." + tag + ".keyalgorithm", cdata.getKeyAlgorithm());
        cs.putString("preop.cert." + tag + ".keytype", cdata.getKeyType());
    }

    private void updateConfiguration(ConfigurationRequest data, SystemCertData cdata, String tag) {
        if (CryptoUtil.isInternalToken(cdata.getToken())) {
            cs.putString(csSubsystem + ".cert." + tag + ".nickname", cdata.getNickname());
        } else {
            cs.putString(csSubsystem + ".cert." + tag + ".nickname", data.getToken() +
                    ":" + cdata.getNickname());
        }

        cs.putString(csSubsystem + "." + tag + ".nickname", cdata.getNickname());
        cs.putString(csSubsystem + "." + tag + ".tokenname", cdata.getToken());
        cs.putString(csSubsystem + "." + tag + ".certreq", cdata.getRequest());
        cs.putString(csSubsystem + "." + tag + ".cert", cdata.getCert());
        cs.putString(csSubsystem + "." + tag + ".dn", cdata.getSubjectDN());
    }

    public void backupKeys(ConfigurationRequest request) {
        try {
            ConfigurationUtils.backupKeys(request.getBackupPassword(), request.getBackupFile());
        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Error in creating pkcs12 to backup keys and certs: " + e);
        }
    }

    public void finalizeConfiguration(ConfigurationRequest request) {
    }

    public void configureAdministrator(ConfigurationRequest data, ConfigurationResponse response) {

        if (!data.isClone()) {
            try {
                X509CertImpl admincerts[] = new X509CertImpl[1];
                ConfigurationUtils.createAdmin(data.getAdminUID(), data.getAdminEmail(),
                        data.getAdminName(), data.getAdminPassword());

                if (data.getImportAdminCert().equalsIgnoreCase("true")) {
                    String b64 = CryptoUtil.stripCertBrackets(data.getAdminCert().trim());
                    b64 = CryptoUtil.normalizeCertStr(b64);
                    if (data.getStandAlone() && data.getStepTwo()) {
                        // Stand-alone PKI (Step 2)
                        CMS.debug("SystemConfigService:  Stand-alone " + csType + " Admin Cert");
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
                CMS.debug(e);
                throw new PKIException("Error in creating admin user: " + e);
            }
        }
    }

    public void configureDatabase(ConfigurationRequest data) {
        cs.putString("internaldb.ldapconn.host", data.getDsHost());
        cs.putString("internaldb.ldapconn.port", data.getDsPort());
        cs.putString("internaldb.database", data.getDatabase());
        cs.putString("internaldb.basedn", data.getBaseDN());
        cs.putString("internaldb.ldapauth.bindDN", data.getBindDN());
        cs.putBoolean("internaldb.ldapconn.secureConn", data.getSecureConn().equals("true"));
        cs.putString("preop.database.removeData", data.getRemoveData());
        cs.putBoolean("preop.database.createNewDB", data.getCreateNewDB());
        cs.putBoolean("preop.database.setupReplication", data.getSetupReplication());
        cs.putBoolean("preop.database.reindexData", data.getReindexData());
    }

    public void initializeDatabase(ConfigurationRequest data) {

        if (data.isClone() && data.getSetupReplication()) {
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
            if ((cloneReplicationPort == data.getDsPort()) && (data.getSecureConn().equals("true"))) {
                replicationSecurity = "SSL";
            } else if (replicationSecurity == null) {
                replicationSecurity = "None";
            }
            cs.putString("internaldb.ldapconn.replicationSecurity", replicationSecurity);

            cs.putString("preop.internaldb.replicateSchema", data.getReplicateSchema());
        }

        try {
            /* BZ 430745 create password for replication manager */
            // use user-provided password if specified
            String replicationPassword = data.getReplicationPassword();

            if (StringUtils.isEmpty(replicationPassword)) {
                // generate random password
                replicationPassword = Integer.toString(new Random().nextInt());
            }

            IConfigStore psStore = null;
            String passwordFile = null;
            passwordFile = cs.getString("passwordFile");
            psStore = CMS.createFileConfigStore(passwordFile);
            psStore.putString("internaldb", data.getBindpwd());
            if (StringUtils.isEmpty(psStore.getString("replicationdb", null))) {
                psStore.putString("replicationdb", replicationPassword);
            }
            psStore.commit(false);

            if (!data.getStepTwo()) {
                ConfigurationUtils.enableUSNPlugin();
                ConfigurationUtils.populateDB();

                cs.putString("preop.internaldb.replicationpwd", replicationPassword);
                cs.putString("preop.database.removeData", "false");
                if (data.getSharedDB()) {
                    cs.putString("preop.internaldb.dbuser", data.getSharedDBUserDN());
                }
                cs.commit(false);

                if (data.isClone() && data.getSetupReplication()) {
                    CMS.debug("Start setting up replication.");
                    ConfigurationUtils.setupReplication();
                }

                ConfigurationUtils.populateDBManager();
                ConfigurationUtils.populateVLVIndexes();
            }
        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Error in populating database: " + e, e);
        }
    }

    public void configureHierarchy(ConfigurationRequest data) {
        if (csType.equals("CA") && !data.isClone()) {
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

    public void configureCACertChain(ConfigurationRequest data, String domainXML) {
        if (data.getHierarchy() == null || data.getHierarchy().equals("join")) {
            try {
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

                    if (!data.isClone() && !data.getSystemCertsImported()) {
                        ConfigurationUtils.importCertChain(host, admin_port, "/ca/admin/ca/getCertChain", "ca");
                    }

                    if (csType.equals("CA")) {
                        cs.putString("preop.cert.signing.type", "remote");
                        cs.putString("preop.cert.signing.profile","caInstallCACert");
                    }
                }
            } catch (Exception e) {
                throw new PKIException("Error in obtaining certificate chain from issuing CA: " + e);
            }
        }
    }

    private void configureClone(ConfigurationRequest data, Collection<String> certList, String token, String domainXML) throws Exception {
        for (String tag : certList) {
            if (tag.equals("sslserver")) {
                cs.putBoolean("preop.cert." + tag + ".enable", true);
            } else {
                cs.putBoolean("preop.cert." + tag + ".enable", false);
            }
        }

        String cloneUri = data.getCloneUri();
        URL url = new URL(cloneUri);
        String masterHost = url.getHost();
        int masterPort = url.getPort();

        CMS.debug("SystemConfigService: validate clone URI: " + url);
        boolean validCloneUri = ConfigurationUtils.isValidCloneURI(domainXML, masterHost, masterPort);

        if (!validCloneUri) {
            throw new BadRequestException(
                    "Clone URI does not match available subsystems: " + url);
        }

        if (csType.equals("CA") && !data.getSystemCertsImported()) {
            CMS.debug("SystemConfigService: import certificate chain from master");
            int masterAdminPort = ConfigurationUtils.getPortFromSecurityDomain(domainXML,
                    masterHost, masterPort, "CA", "SecurePort", "SecureAdminPort");
            ConfigurationUtils.importCertChain(masterHost, masterAdminPort,
                    "/ca/admin/ca/getCertChain", "clone");
        }

        CMS.debug("SystemConfigService: get configuration entries from master");
        ConfigurationUtils.getConfigEntriesFromMaster();

        if (CryptoUtil.isInternalToken(token)) {
            if (!data.getSystemCertsImported()) {
                CMS.debug("SystemConfigService: restore certificates from P12 file");
                String p12File = data.getP12File();
                String p12Pass = data.getP12Password();
                ConfigurationUtils.restoreCertsFromP12(p12File, p12Pass);
            }

        } else {
            CMS.debug("SystemConfigService: import certificates from HSM and set permission");
            ConfigurationUtils.importAndSetCertPermissionsFromHSM();
        }

        CMS.debug("SystemConfigService: verify certificates");
        ConfigurationUtils.verifySystemCertificates();
    }

    public String configureSecurityDomain(ConfigurationRequest data) throws Exception {

        String domainXML = null;

        String securityDomainType = data.getSecurityDomainType();
        String securityDomainName = data.getSecurityDomainName();

        if (securityDomainType.equals(ConfigurationRequest.NEW_DOMAIN)) {
            configureNewSecurityDomain(data, securityDomainName);
        } else if (securityDomainType.equals(ConfigurationRequest.NEW_SUBDOMAIN)){
            CMS.debug("Configuring new subordinate root CA");
            configureNewSecurityDomain(data, data.getSubordinateSecurityDomainName());
            String securityDomainURL = data.getSecurityDomainUri();
            domainXML = logIntoSecurityDomain(data, securityDomainURL);
        } else {
            CMS.debug("Joining existing security domain");
            cs.putString("preop.securitydomain.select", "existing");
            cs.putString("securitydomain.select", "existing");
            cs.putString("preop.cert.subsystem.type", "remote");
            cs.putString("preop.cert.subsystem.profile", "caInternalAuthSubsystemCert");
            String securityDomainURL = data.getSecurityDomainUri();
            domainXML = logIntoSecurityDomain(data, securityDomainURL);
        }
        return domainXML;
    }

    private void configureNewSecurityDomain(ConfigurationRequest data, String securityDomainName) {
        CMS.debug("Creating new security domain");
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
    }

    private String logIntoSecurityDomain(ConfigurationRequest data, String securityDomainURL) throws Exception {
        URL secdomainURL;
        String host;
        int port;
        try {
            CMS.debug("Resolving security domain URL " + securityDomainURL);
            secdomainURL = new URL(securityDomainURL);
            host = secdomainURL.getHost();
            port = secdomainURL.getPort();
            cs.putString("securitydomain.host", host);
            cs.putInteger("securitydomain.httpsadminport",port);
        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Failed to resolve security domain URL", e);
        }

        if (!data.getSystemCertsImported()) {
            CMS.debug("Getting security domain cert chain");
            ConfigurationUtils.importCertChain(host, port, "/ca/admin/ca/getCertChain", "securitydomain");
        }

        getInstallToken(data, host, port);

        return getDomainXML(host, port);
    }

    private String getDomainXML(String host, int port) {
        CMS.debug("Getting domain XML");
        String domainXML = null;
        try {
            domainXML = ConfigurationUtils.getDomainXML(host, port, true);
            ConfigurationUtils.getSecurityDomainPorts(domainXML, host, port);
        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Failed to obtain security domain decriptor from security domain master: " + e, e);
        }
        return domainXML;
    }

    private void getInstallToken(ConfigurationRequest data, String host, int port) {
        CMS.debug("Getting install token");
        // log onto security domain and get token
        String user = data.getSecurityDomainUser();
        String pass = data.getSecurityDomainPassword();
        String installToken;
        try {
            installToken = ConfigurationUtils.getInstallToken(host, port, user, pass);
        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Failed to obtain installation token from security domain: " + e, e);
        }

        if (installToken == null) {
            CMS.debug("Install token is null");
            throw new PKIException("Failed to obtain installation token from security domain");
        }
        CMS.setConfigSDSessionId(installToken);
    }

    public void configureSubsystem(ConfigurationRequest request,
            Collection<String> certList, String token, String domainXML) throws Exception {

        cs.putString("preop.subsystem.name", request.getSubsystemName());

        // is this a clone of another subsystem?
        if (!request.isClone()) {
            cs.putString("preop.subsystem.select", "new");
            cs.putString("subsystem.select", "New");

        } else {
            cs.putString("preop.subsystem.select", "clone");
            cs.putString("subsystem.select", "Clone");
            configureClone(request, certList, token, domainXML);
        }
    }

    public void loginToken(ConfigurationRequest data, String token) {
        cs.putString("preop.module.token", token);

        if (!CryptoUtil.isInternalToken(token)) {
            try {
                CryptoToken ctoken = CryptoUtil.getKeyStorageToken(token);
                String tokenpwd = data.getTokenPassword();
                ConfigurationUtils.loginToken(ctoken, tokenpwd);
            } catch (NotInitializedException e) {
                throw new PKIException("Token is not initialized", e);
            } catch (NoSuchTokenException e) {
                throw new BadRequestException("Invalid Token provided. No such token.", e);
            } catch (TokenException e) {
                CMS.debug(e);
                throw new PKIException("Token Exception: " + e, e);
            } catch (IncorrectPasswordException e) {
                throw new BadRequestException("Incorrect Password provided for token.", e);
            }
        }
    }

    private void validateRequest(ConfigurationRequest data) throws Exception {

        // validate installation pin
        String pin = data.getPin();
        if (pin == null) {
            throw new BadRequestException("No preop pin provided");
        }

        String preopPin = cs.getString("preop.pin");
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
            if (data.isClone()) {
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

        } else if (domainType.equals(ConfigurationRequest.EXISTING_DOMAIN) ||
                   domainType.equals(ConfigurationRequest.NEW_SUBDOMAIN)) {
            if (data.getStandAlone()) {
                throw new BadRequestException("Existing security domains are not valid for stand-alone PKI subsytems");
            }

            String domainURI = data.getSecurityDomainUri();
            if (domainURI == null) {
                throw new BadRequestException("Existing security domain requested, but no security domain URI provided");
            }

            try {
                new URL(domainURI);
            } catch (MalformedURLException e) {
                throw new BadRequestException("Invalid security domain URI: " + domainURI, e);
            }

            if ((data.getSecurityDomainUser() == null) || (data.getSecurityDomainPassword() == null)) {
                throw new BadRequestException("Security domain user or password not provided");
            }

        } else {
            throw new BadRequestException("Invalid security domain URI provided");
        }

        // validate subordinate CA security domain settings
        if (domainType.equals(ConfigurationRequest.NEW_SUBDOMAIN)) {
            if (StringUtils.isEmpty(data.getSubordinateSecurityDomainName())) {
                throw new BadRequestException("Subordinate CA security domain name not provided");
            }
        }

        if ((data.getSubsystemName() == null) || (data.getSubsystemName().length() ==0)) {
            throw new BadRequestException("Invalid or no subsystem name provided");
        }

        if (data.isClone()) {
            String cloneUri = data.getCloneUri();
            if (cloneUri == null) {
                throw new BadRequestException("Clone selected, but no clone URI provided");
            }
            try {
                URL url = new URL(cloneUri);
                // confirm protocol is https
                if (!"https".equals(url.getProtocol())) {
                    throw new BadRequestException("Clone URI must use HTTPS protocol: " + cloneUri);
                }
            } catch (MalformedURLException e) {
                throw new BadRequestException("Invalid clone URI: " + cloneUri, e);
            }

            if (CryptoUtil.isInternalToken(data.getToken())) {
                if (!data.getSystemCertsImported()) {
                    if (data.getP12File() == null) {
                        throw new BadRequestException("P12 filename not provided");
                    }

                    if (data.getP12Password() == null) {
                        throw new BadRequestException("P12 password not provided");
                    }
                }
            } else {
                if (data.getP12File() != null) {
                    throw new BadRequestException("P12 filename should not be provided since HSM clones must share their HSM master's private keys");
                }

                if (data.getP12Password() != null) {
                    throw new BadRequestException("P12 password should not be provided since HSM clones must share their HSM master's private keys");
                }
            }

        } else {
            data.setClone("false");
        }

        String dsHost = data.getDsHost();
        if (dsHost == null || dsHost.length() == 0) {
            throw new BadRequestException("Internal database host not provided");
        }

        try {
            Integer.parseInt(data.getDsPort());  // check for errors
        } catch (NumberFormatException e) {
            throw new BadRequestException("Internal database port is invalid: " + data.getDsPort(), e);
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
                throw new BadRequestException("Master replication port is invalid: " + masterReplicationPort, e);
            }
        }

        String cloneReplicationPort = data.getCloneReplicationPort();
        if (cloneReplicationPort != null && cloneReplicationPort.length() > 0) {
            try {
                Integer.parseInt(cloneReplicationPort); // check for errors
            } catch (NumberFormatException e) {
                throw new BadRequestException("Clone replication port is invalid: " + cloneReplicationPort, e);
            }
        }

        if ((data.getReplicateSchema() != null) && (data.getReplicateSchema().equalsIgnoreCase("false"))) {
            data.setReplicateSchema("false");
        } else {
            data.setReplicateSchema("true");
        }

        if ((data.getBackupKeys() != null) && data.getBackupKeys().equals("true")) {
            if (! data.getToken().equals(CryptoUtil.INTERNAL_TOKEN_FULL_NAME)) {
                throw new BadRequestException("HSMs cannot publish private keys to PKCS #12 files");
            }

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

        if (!data.isClone()) {
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

        if (! data.getGenerateSubsystemCert()) {
            // No subsystem cert to be generated.  All interactions use a shared subsystem cert.
            if (data.getSharedDB() && StringUtils.isEmpty(data.getSharedDBUserDN())) {
                throw new BadRequestException("Shared db user DN not provided");
            }
        } else {
            // if the subsystem cert is not shared, we do not need to worry about sharing the db
            data.setSharedDB("false");
        }

        if (csType.equals("TPS")) {
            if (data.getCaUri() == null) {
                throw new BadRequestException("CA URI not provided");
            }

            if (data.getTksUri() == null) {
                throw new BadRequestException("TKS URI not provided");
            }

            if (data.getEnableServerSideKeyGen().equalsIgnoreCase("true")) {
                if (data.getKraUri() == null) {
                    throw new BadRequestException("KRA URI required if server-side key generation requested");
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
                throw new BadRequestException("Authentication Database port is invalid: " + data.getAuthdbPort(), e);
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
