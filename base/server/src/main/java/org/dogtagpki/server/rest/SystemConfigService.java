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

import java.security.KeyPair;

import javax.ws.rs.POST;
import javax.ws.rs.Path;

import org.apache.commons.codec.binary.Hex;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.netscape.security.x509.Extension;
import org.mozilla.jss.netscape.security.x509.Extensions;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.pkcs11.PK11PubKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.base.PKIException;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.cms.servlet.base.PKIService;
import com.netscape.cms.servlet.csadmin.Configurator;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author alee
 *
 */
@Path("installer")
public class SystemConfigService extends PKIService {

    public final static Logger logger = LoggerFactory.getLogger(SystemConfigService.class);

    public Configurator configurator;

    public EngineConfig cs;
    public String csType;
    public String csSubsystem;
    public String csState;
    public boolean isMasterCA = false;
    public String instanceRoot;

    public SystemConfigService() throws Exception {

        CMSEngine engine = CMS.getCMSEngine();
        cs = engine.getConfig();

        csType = cs.getType();
        csSubsystem = csType.toLowerCase();
        csState = cs.getState() + "";

        String domainType = cs.getString("securitydomain.select", "existingdomain");
        if (csType.equals("CA") && domainType.equals("new")) {
            isMasterCA = true;
        }

        instanceRoot = cs.getInstanceDir();

        configurator = engine.createConfigurator();
    }

    @POST
    @Path("importRequest")
    public SystemCertData importRequest(CertificateSetupRequest request) throws Exception {

        String tag = request.getTag();
        logger.info("SystemConfigService: Importing " + tag + " cert request");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            SystemCertData certData = request.getSystemCert();

            String profileID = certData.getProfile();
            String[] dnsNames = certData.getDNSNames();

            String certRequestType = certData.getRequestType();
            String certRequest = certData.getRequest();
            byte[] binCertRequest = Utils.base64decode(certRequest);

            boolean installAdjustValidity = certData.getAdjustValidity();
            logger.info("SystemConfigService: - adjust validity: " + installAdjustValidity);

            RequestId requestID = configurator.createRequestID();
            certData.setRequestID(requestID);

            configurator.importRequest(
                    requestID,
                    profileID,
                    dnsNames,
                    installAdjustValidity,
                    certRequestType,
                    binCertRequest);

            return certData;

        } catch (PKIException e) { // normal response
            logger.error("Unable to import " + tag + " certificate request: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Unable to import " + tag + " certificate request: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("setupKey")
    public SystemCertData setupKey(CertificateSetupRequest request) throws Exception {

        String tag = request.getTag();
        logger.info("SystemConfigService: Setting up " + tag + " key");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            SystemCertData certData = request.getSystemCert();

            String nickname = certData.getNickname();
            logger.info("SystemConfigService: - nickname: " + nickname);

            String tokenName = certData.getToken();
            logger.info("SystemConfigService: - token: " + tokenName);

            String fullName = nickname;
            if (!CryptoUtil.isInternalToken(tokenName)) {
                fullName = tokenName + ":" + nickname;
            }

            CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

            X509Certificate x509Cert;
            KeyPair keyPair;

            try {
                logger.info("SystemConfigService: Loading " + tag + " cert from NSS database: " + fullName);
                CryptoManager cm = CryptoManager.getInstance();
                x509Cert = cm.findCertByNickname(fullName);

                logger.info("SystemConfigService: Loading " + tag + " key pair from NSS database");
                keyPair = configurator.loadKeyPair(x509Cert);

            } catch (ObjectNotFoundException e) {
                logger.info("SystemConfigService: " + tag + " cert not found: " + fullName);
                x509Cert = null;

                String keyType = certData.getKeyType();
                String keySize = certData.getKeySize();

                if (keyType.equals("ecc")) {
                    String ecType = certData.getEcType();
                    keyPair = configurator.createECCKeyPair(tag, token, keySize, ecType);

                } else {
                    keyPair = configurator.createRSAKeyPair(tag, token, keySize);
                }
            }

            PrivateKey privateKey = (PrivateKey) keyPair.getPrivate();
            String keyID = Hex.encodeHexString(privateKey.getUniqueID());
            logger.info("SystemConfigService: - key ID: " + keyID);
            certData.setKeyID(keyID);

            return certData;

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("createRequest")
    public SystemCertData createRequest(CertificateSetupRequest request) throws Exception {

        String tag = request.getTag();
        logger.info("SystemConfigService: Creating " + tag + " cert request");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            SystemCertData certData = request.getSystemCert();

            String tokenName = certData.getToken();
            logger.info("SystemConfigService: - token: " + tokenName);
            CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

            String keyID = certData.getKeyID();
            logger.info("SystemConfigService: - key ID: " + keyID);

            PK11PrivKey privateKey = (PK11PrivKey) CryptoUtil.findPrivateKey(
                    token,
                    Hex.decodeHex(keyID));

            PK11PubKey publicKey = privateKey.getPublicKey();
            KeyPair keyPair = new KeyPair(publicKey, privateKey);

            Extensions requestExtensions = new Extensions();
            if (tag.equals("signing")) {
                configurator.createBasicCAExtensions(requestExtensions);
            }

            String extOID = certData.getReqExtOID();
            String extData = certData.getReqExtData();
            boolean extCritical = certData.getReqExtCritical();

            if (extOID != null && extData != null) {
                Extension ext = configurator.createGenericExtension(extOID, extData, extCritical);
                requestExtensions.add(ext);
            }

            String subjectDN = certData.getSubjectDN();
            String keyAlgorithm = certData.getKeyAlgorithm();

            String certRequestType = certData.getRequestType();
            logger.info("SystemConfigService: - request type: " + certRequestType);

            byte[] binCertRequest;

            if (certRequestType.equals("pkcs10")) {

                PKCS10 pkcs10 = configurator.createPKCS10Request(
                        keyPair,
                        subjectDN,
                        keyAlgorithm,
                        requestExtensions);

                binCertRequest = pkcs10.toByteArray();

            } else {
                throw new Exception("Certificate request type not supported: " + certRequestType);
            }

            certData.setRequest(CryptoUtil.base64Encode(binCertRequest));

            return certData;

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("createCert")
    public SystemCertData createCert(CertificateSetupRequest request) throws Exception {

        String tag = request.getTag();
        logger.info("SystemConfigService: Creating " + tag + " cert");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            SystemCertData certData = request.getSystemCert();

            RequestId requestID = certData.getRequestID();

            String certRequestType = certData.getRequestType();
            logger.info("SystemConfigService: - request type: " + certRequestType);

            String certRequest = certData.getRequest();
            byte[] binCertRequest = CryptoUtil.base64Decode(certRequest);

            X500Name subjectName;
            X509Key x509key;

            if (certRequestType.equals("crmf")) {
                SEQUENCE crmfMsgs = CryptoUtil.parseCRMFMsgs(binCertRequest);
                subjectName = CryptoUtil.getSubjectName(crmfMsgs);
                x509key = CryptoUtil.getX509KeyFromCRMFMsgs(crmfMsgs);

            } else if (certRequestType.equals("pkcs10")) {
                PKCS10 pkcs10 = new PKCS10(binCertRequest);
                subjectName = pkcs10.getSubjectName();
                x509key = pkcs10.getSubjectPublicKeyInfo();

            } else {
                throw new Exception("Certificate request type not supported: " + certRequestType);
            }

            // cert type is selfsign or local
            String certType = certData.getType();
            logger.info("SystemConfigService: - cert type: " + certType);

            String profileID = certData.getProfile();
            logger.info("SystemConfigService: - profile: " + profileID);

            String keyAlgorithm = certData.getKeyAlgorithm();
            logger.info("SystemConfigService: - key algorithm: " + keyAlgorithm);

            X500Name issuerName;
            PrivateKey signingPrivateKey;

            if (certType.equals("selfsign")) {

                String tokenName = certData.getToken();
                logger.info("SystemConfigService: - token: " + tokenName);
                CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

                String keyID = certData.getKeyID();
                logger.info("SystemConfigService: - key ID: " + keyID);

                PK11PrivKey privateKey = (PK11PrivKey) CryptoUtil.findPrivateKey(
                        token,
                        Hex.decodeHex(keyID));

                PK11PubKey publicKey = privateKey.getPublicKey();
                KeyPair keyPair = new KeyPair(publicKey, privateKey);

                issuerName = subjectName;
                signingPrivateKey = (PrivateKey) keyPair.getPrivate();

            } else { // certType == local
                issuerName = null;
                signingPrivateKey = null;
            }

            String signingAlgorithm = certData.getSigningAlgorithm();
            logger.info("SystemConfigService: - signing algorithm: " + signingAlgorithm);

            X509CertImpl certImpl = configurator.createCert(
                    requestID,
                    keyAlgorithm,
                    x509key,
                    profileID,
                    signingPrivateKey,
                    signingAlgorithm,
                    certRequestType,
                    binCertRequest,
                    issuerName,
                    subjectName);

            byte[] binCert = certImpl.getEncoded();
            certData.setCert(CryptoUtil.base64Encode(binCert));

            return certData;

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("initSubsystem")
    public void initSubsystem(CertificateSetupRequest request) throws Exception {

        logger.info("SystemConfigService: Initializing subsystem");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            configurator.initSubsystem();

        } catch (PKIException e) { // normal response
            logger.error("Configuration failed: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Configuration failed: " + e.getMessage(), e);
            throw e;
        }
    }

    private void validatePin(String pin) throws Exception {

        if (pin == null) {
            throw new BadRequestException("Missing configuration PIN");
        }

        PreOpConfig preopConfig = cs.getPreOpConfig();

        String preopPin = preopConfig.getString("pin");
        if (!preopPin.equals(pin)) {
            throw new BadRequestException("Invalid configuration PIN");
        }
    }
}
