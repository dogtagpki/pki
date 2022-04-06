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
import org.dogtagpki.nss.NSSDatabase;
import org.dogtagpki.nss.NSSExtensionGenerator;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.KeyPairGeneratorSpi.Usage;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.util.Utils;
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
    @Path("createRequestID")
    public RequestId createRequestID(CertificateSetupRequest request) throws Exception {
        String tag = request.getTag();
        logger.info("SystemConfigService: Creating cert request ID");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            RequestId requestID = configurator.createRequestID();
            logger.info("SystemConfigService: - request ID: " + requestID.toHexString());

            return requestID;

        } catch (PKIException e) { // normal response
            logger.error("Unable to import " + tag + " certificate request: " + e.getMessage());
            throw e;

        } catch (Throwable e) { // unexpected error
            logger.error("Unable to import " + tag + " certificate request: " + e.getMessage(), e);
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

            NSSDatabase nssdb = new NSSDatabase();

            String tokenName = certData.getToken();
            logger.info("SystemConfigService: - token: " + tokenName);
            CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

            String keyID = certData.getKeyID();
            logger.info("SystemConfigService: - key ID: " + keyID);

            String keyType = certData.getKeyType();
            KeyPair keyPair;

            if (keyID != null) {

                logger.info("SystemConfigService: Loading key pair");
                if (keyID.startsWith("0x")) keyID = keyID.substring(2);
                if (keyID.length() % 2 == 1) keyID = "0" + keyID;
                keyPair = nssdb.loadKeyPair(token, Hex.decodeHex(keyID));

            } else if ("RSA".equalsIgnoreCase(keyType)) {

                logger.info("SystemConfigService: Creating RSA key pair");

                String keySize = certData.getKeySize();
                logger.info("SystemConfigService: - key size: " + keySize);

                boolean keyWrap = certData.getKeyWrap();
                logger.info("SystemConfigService: - key wrap: " + keyWrap);

                Usage[] usages;
                Usage[] usagesMask;

                if (keyWrap) {
                    usages = CryptoUtil.RSA_KEYPAIR_USAGES;
                    usagesMask = CryptoUtil.RSA_KEYPAIR_USAGES_MASK;

                } else {
                    usages = null;
                    usagesMask = null;
                }

                keyPair = nssdb.createRSAKeyPair(
                        token,
                        Integer.parseInt(keySize),
                        usages,
                        usagesMask);

            } else if ("EC".equalsIgnoreCase(keyType)) {

                logger.info("SystemConfigService: Creating ECC key pair");

                String curveName = certData.getKeyCurveName();
                logger.info("SystemConfigService: - curve: " + curveName);

                boolean sslECDH = certData.getSslECDH();
                logger.info("SystemConfigService: - SSL ECDH: " + sslECDH);

                Usage[] usages;
                Usage[] usagesMask;

                if (sslECDH) {
                    usages = null;
                    usagesMask = CryptoUtil.ECDH_USAGES_MASK;

                } else {
                    usages = null;
                    usagesMask = CryptoUtil.ECDHE_USAGES_MASK;
                }

                keyPair = nssdb.createECKeyPair(
                        token,
                        curveName,
                        usages,
                        usagesMask);

            } else {
                throw new Exception("Unsupported key type: " + keyType);
            }

            PrivateKey privateKey = (PrivateKey) keyPair.getPrivate();

            keyID = "0x" + Utils.HexEncode(privateKey.getUniqueID());
            certData.setKeyID(keyID);

            NSSExtensionGenerator generator = new NSSExtensionGenerator();

            if (tag.equals("signing")) {
                // create BasicConstraintsExtension
                generator.setParameter(
                        "basicConstraints",
                        "CA:TRUE,pathlen:-1,critical");

                // create KeyUsageExtension
                generator.setParameter(
                        "keyUsage",
                        "digitalSignature,nonRepudiation,keyCertSign,cRLSign,critical");

                // create NSCertTypeExtension (not supported)
                // generator.setParameter(
                //         "nsCertType",
                //         "ssl_ca");
            }

            String extOID = certData.getReqExtOID();
            String extData = certData.getReqExtData();
            boolean extCritical = certData.getReqExtCritical();

            if (extOID != null && extData != null) {
                // create generic Extension

                // split extension data
                // e.g. "abcdef" => ["ab", "cd", "ef"]
                String[] array = extData.split("(?<=\\G.{2})");

                // rejoin extension data
                // e.g. ["ab", "cd", "ef"] => "DER:ab:cd:ef"
                String der = "DER:" + String.join(":", array);

                String value = der;
                if (extCritical) {
                    value = value + ",critical";
                }

                generator.setParameter(extOID, value);
            }

            Extensions requestExtensions = generator.createExtensions();

            String subjectDN = certData.getSubjectDN();
            String keyAlgorithm = certData.getKeyAlgorithm();

            String certRequestType = certData.getRequestType();
            logger.info("SystemConfigService: - request type: " + certRequestType);

            byte[] binCertRequest;

            if (certRequestType.equals("pkcs10")) {

                PKCS10 pkcs10 = nssdb.createPKCS10Request(
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

                if (keyID.startsWith("0x")) keyID = keyID.substring(2);
                if (keyID.length() % 2 == 1) keyID = "0" + keyID;
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
