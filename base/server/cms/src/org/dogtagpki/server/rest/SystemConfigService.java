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
import java.net.URISyntaxException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Random;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Request;
import javax.ws.rs.core.UriInfo;

import netscape.security.x509.X509CertImpl;

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
     * @see com.netscape.cms.servlet.csadmin.SystemConfigurationResource#configure(javax.ws.rs.core.MultivaluedMap)
     */
    @Override
    public ConfigurationResponse configure(MultivaluedMap<String, String> form) throws URISyntaxException {
        ConfigurationRequest data = new ConfigurationRequest(form);
        return configure(data);
    }

    /* (non-Javadoc)
     * @see com.netscape.cms.servlet.csadmin.SystemConfigurationResource#configure(com.netscape.cms.servlet.csadmin.data.ConfigurationData)
     */
    @Override
    public ConfigurationResponse configure(ConfigurationRequest request) {
        try {
            ConfigurationResponse response = new ConfigurationResponse();
            configure(request, response);
            return response;

        } catch (Throwable t) {
            CMS.debug(t);
            throw t;
        }
    }

    public void configure(ConfigurationRequest data, ConfigurationResponse response) {

        if (csState.equals("1")) {
            throw new BadRequestException("System is already configured");
        }

        CMS.debug("SystemConfigService(): configure() called");
        CMS.debug(data.toString());

        validateData(data);

        Collection<String> certList = getCertList(data);

        // specify module and log into token
        CMS.debug("=== Token Panel ===");
        String token = data.getToken();
        if (token == null) {
            token = ConfigurationRequest.TOKEN_DEFAULT;
        }
        loginToken(data, token);

        //configure security domain
        CMS.debug("=== Security Domain Panel ===");
        String domainXML = configureSecurityDomain(data);

        //subsystem panel
        CMS.debug("=== Subsystem Panel ===");
        configureSubsystem(data, certList, token, domainXML);

        // Hierarchy Panel
        CMS.debug("=== Hierarchy Panel ===");
        configureHierarchy(data);

        // Database Panel
        CMS.debug("=== Database Panel ===");
        try {
            configureDatabase(data);
            cs.commit(false);
        } catch (EBaseException e) {
            CMS.debug(e);
            throw new PKIException("Unable to commit config parameters to file");
        }
        initializeDatabase(data);

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
            backupKeys(data);
        }

        // AdminPanel
        CMS.debug("=== Admin Panel ===");
        configureAdministrator(data, response);

        // Done Panel
        // Create or update security domain
        CMS.debug("=== Done Panel ===");
        try {
            String securityDomainType = data.getSecurityDomainType();
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

        try {
            if (!data.getSharedDB()) ConfigurationUtils.setupDBUser();
        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Errors in creating or updating dbuser: " + e);
        }

        finalizeConfiguration(data);

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
                        CMS.debug("Found data for '" + tag + "'");
                        if (tag.equals("signing") &&
                                certData.getReqExtOID() != null &&
                                certData.getReqExtData() != null) {
                            CMS.debug("SystemConfigService:processCerts: adding request extension to config");
                            cs.putString("preop.cert.signing.ext.oid", certData.getReqExtOID());
                            cs.putString("preop.cert.signing.ext.data", certData.getReqExtData());
                            cs.putBoolean("preop.cert.signing.ext.critical", certData.getReqExtCritical());
                        }
                        break;
                    }
                }

                if (certData == null) {
                    CMS.debug("No data for '" + tag + "' was found!");
                    throw new BadRequestException("No data for '" + tag + "' was found!");
                }

                if (request.getStandAlone() && request.getStepTwo()) {
                    // Stand-alone PKI (Step 2)
                    if (tag.equals("external_signing")) {

                        String b64 = certData.getCert();
                        if (b64 != null && b64.length() > 0 && !b64.startsWith("...")) {
                            hasSigningCert.setValue(true);

                            if (request.getIssuingCA().equals("External CA")) {
                                String nickname = certData.getNickname() != null ? certData.getNickname() : "caSigningCert External CA";
                                String tokenName = certData.getToken() != null ? certData.getToken() : token;
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
                    updateCloneConfiguration(certData, "subsystem");
                    continue;
                }

                String keytype = certData.getKeyType() != null ? certData.getKeyType() : "rsa";

                String keyalgorithm = certData.getKeyAlgorithm();
                if (keyalgorithm == null) {
                    keyalgorithm = keytype.equals("ecc") ? "SHA256withEC" : "SHA256withRSA";
                }

                String signingalgorithm = certData.getSigningAlgorithm() != null ? certData.getSigningAlgorithm() : keyalgorithm;
                String nickname = certData.getNickname() != null ? certData.getNickname() :
                    cs.getString("preop.cert." + tag + ".nickname");
                String dn = certData.getSubjectDN() != null ? certData.getSubjectDN() :
                    cs.getString("preop.cert." + tag + ".dn");

                cs.putString("preop.cert." + tag + ".keytype", keytype);
                cs.putString("preop.cert." + tag + ".keyalgorithm", keyalgorithm);
                cs.putString("preop.cert." + tag + ".signingalgorithm", signingalgorithm);
                cs.putString("preop.cert." + tag + ".nickname", nickname);
                cs.putString("preop.cert." + tag + ".dn", dn);
                cs.commit(false);

                if (!request.getStepTwo()) {
                    if (keytype.equals("ecc")) {
                        String curvename = certData.getKeyCurveName() != null ?
                                certData.getKeyCurveName() : cs.getString("keys.ecc.curve.default");
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

                String tokenName = certData.getToken() != null ? certData.getToken() : token;
                Cert cert = new Cert(tokenName, nickname, tag);
                cert.setDN(dn);
                cert.setSubsystem(cs.getString("preop.cert." + tag + ".subsystem"));
                cert.setType(cs.getString("preop.cert." + tag + ".type"));

                if (!request.getStepTwo()) {
                    ConfigurationUtils.configCert(null, null, null, cert, null);

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

                // Handle Cert Requests for everything EXCEPT Stand-alone PKI (Step 2)
                if (request.getStandAlone()) {
                    if (!request.getStepTwo()) {
                        // Stand-alone PKI (Step 1)
                        ConfigurationUtils.handleCertRequest(cs, tag, cert);

                        CMS.debug("Stand-alone " + csType + " Admin CSR");
                        String adminSubjectDN = request.getAdminSubjectDN();
                        String certreqStr = request.getAdminCertRequest();
                        certreqStr = CryptoUtil.normalizeCertAndReq(certreqStr);

                        cs.putString("preop.cert.admin.dn", adminSubjectDN);
                        cs.putString(csSubsystem + ".admin.certreq", certreqStr);
                        cs.putString(csSubsystem + ".admin.cert", "...paste certificate here...");
                    }

                } else {
                    ConfigurationUtils.handleCertRequest(cs, tag, cert);
                }

                if (request.isClone()) {
                    ConfigurationUtils.updateCloneConfig();
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

            // make sure to commit changes here for step 1
            cs.commit(false);

        } catch (NumberFormatException e) {
            // move these validations to validate()?
            throw new BadRequestException("Non-integer value for key size");

        } catch (NoSuchAlgorithmException e) {
            throw new BadRequestException("Invalid algorithm " + e);

        } catch (Exception e) {
            CMS.debug(e);
            throw new PKIException("Error in setting certificate names and key sizes: " + e);
        }
    }

    private void updateCloneConfiguration(SystemCertData cdata, String tag) throws NotInitializedException,
            ObjectNotFoundException, TokenException {
        // TODO - some of these parameters may only be valid for RSA
        CryptoManager cryptoManager = CryptoManager.getInstance();
        X509Certificate cert = cryptoManager.findCertByNickname(cdata.getNickname());
        PublicKey pubk = cert.getPublicKey();
        byte[] exponent = CryptoUtil.getPublicExponent(pubk);
        byte[] modulus = CryptoUtil.getModulus(pubk);
        PrivateKey privk = cryptoManager.findPrivKeyByCert(cert);

        cs.putString("preop.cert." + tag + ".pubkey.modulus", CryptoUtil.byte2string(modulus));
        cs.putString("preop.cert." + tag + ".pubkey.exponent", CryptoUtil.byte2string(exponent));
        cs.putString("preop.cert." + tag + ".privkey.id", CryptoUtil.byte2string(privk.getUniqueID()));
        cs.putString("preop.cert." + tag + ".dn", cdata.getSubjectDN());
        cs.putString("preop.cert." + tag + ".keyalgorithm", cdata.getKeyAlgorithm());
        cs.putString("preop.cert." + tag + ".keytype", cdata.getKeyType());
        cs.putString("preop.cert." + tag + ".nickname", cdata.getNickname());
    }

    private void updateConfiguration(ConfigurationRequest data, SystemCertData cdata, String tag) {
        if (cdata.getToken().equals("Internal Key Storage Token")) {
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

    public void configureDatabase(ConfigurationRequest data) {
        cs.putString("internaldb.ldapconn.host", data.getDsHost());
        cs.putString("internaldb.ldapconn.port", data.getDsPort());
        cs.putString("internaldb.database", data.getDatabase());
        cs.putString("internaldb.basedn", data.getBaseDN());
        cs.putString("internaldb.ldapauth.bindDN", data.getBindDN());
        cs.putBoolean("internaldb.ldapconn.secureConn", data.getSecureConn().equals("on"));
        cs.putString("preop.database.removeData", data.getRemoveData());
        cs.putBoolean("preop.database.createNewDB", data.getCreateNewDB());
        cs.putBoolean("preop.database.setupReplication", data.getSetupReplication());
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
            if (data.getSetupReplication()) {
                psStore.putString("replicationdb", replicationpwd);
            }
            psStore.commit(false);

            if (!data.getStepTwo()) {
                ConfigurationUtils.populateDB();

                cs.putString("preop.internaldb.replicationpwd", replicationpwd);
                cs.putString("preop.database.removeData", "false");
                if (data.getSharedDB()) {
                    cs.putString("preop.internaldb.dbuser", data.getSharedDBUserDN());
                }
                cs.commit(false);

                if (data.isClone() && data.getSetupReplication()) {
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

                    if (!data.isClone()) {
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

    private void getCloningData(ConfigurationRequest data, Collection<String> certList, String token, String domainXML) {
        for (String tag : certList) {
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

    public String configureSecurityDomain(ConfigurationRequest data) {

        String domainXML = null;

        String securityDomainType = data.getSecurityDomainType();
        String securityDomainName = data.getSecurityDomainName();
        String securityDomainURL = data.getSecurityDomainUri();

        if (securityDomainType.equals(ConfigurationRequest.NEW_DOMAIN)) {
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

        } else {
            CMS.debug("Joining existing security domain");
            cs.putString("preop.securitydomain.select", "existing");
            cs.putString("securitydomain.select", "existing");
            cs.putString("preop.cert.subsystem.type", "remote");
            cs.putString("preop.cert.subsystem.profile", "caInternalAuthSubsystemCert");

            CMS.debug("Getting certificate chain");
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

            CMS.debug("Getting install token");
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
                CMS.debug("Install token is null");
                throw new PKIException("Failed to obtain installation token from security domain");
            }
            CMS.setConfigSDSessionId(installToken);

            CMS.debug("Getting domain XML");
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

    public void configureSubsystem(ConfigurationRequest request,
            Collection<String> certList, String token, String domainXML) {

        cs.putString("preop.subsystem.name", request.getSubsystemName());

        // is this a clone of another subsystem?
        if (!request.isClone()) {
            cs.putString("preop.subsystem.select", "new");
            cs.putString("subsystem.select", "New");

        } else {
            cs.putString("preop.subsystem.select", "clone");
            cs.putString("subsystem.select", "Clone");
            getCloningData(request, certList, token, domainXML);
        }
    }

    public void loginToken(ConfigurationRequest data, String token) {
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

        if (data.isClone()) {
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
            data.setClone("false");
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
