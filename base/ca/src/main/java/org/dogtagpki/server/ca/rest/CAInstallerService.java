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
// (C) 2014 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package org.dogtagpki.server.ca.rest;

import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;

import javax.ws.rs.POST;
import javax.ws.rs.Path;

import org.apache.commons.codec.binary.Hex;
import org.dogtagpki.server.ca.CAConfig;
import org.dogtagpki.server.ca.CAEngine;
import org.dogtagpki.server.ca.CAEngineConfig;
import org.dogtagpki.server.rest.SystemConfigService;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.netscape.security.pkcs.PKCS10;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.CertificateIssuerName;
import org.mozilla.jss.netscape.security.x509.CertificateSubjectName;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;
import org.mozilla.jss.netscape.security.x509.X509Key;
import org.mozilla.jss.pkcs11.PK11PrivKey;
import org.mozilla.jss.pkcs11.PK11PubKey;

import com.netscape.ca.CASigningUnit;
import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.BadRequestException;
import com.netscape.certsrv.dbs.certdb.CertId;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.system.CertificateSetupRequest;
import com.netscape.certsrv.system.SystemCertData;
import com.netscape.cms.servlet.csadmin.BootstrapProfile;
import com.netscape.cmscore.apps.PreOpConfig;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.request.CertRequestRepository;
import com.netscape.cmscore.request.Request;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * @author alee
 *
 */
@Path("installer")
public class CAInstallerService extends SystemConfigService {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CAInstallerService.class);

    public CAInstallerService() throws Exception {
    }

    public void validatePin(String pin) throws Exception {

        if (pin == null) {
            throw new BadRequestException("Missing configuration PIN");
        }

        PreOpConfig preopConfig = cs.getPreOpConfig();
        String preopPin = preopConfig.getString("pin");

        if (!preopPin.equals(pin)) {
            throw new BadRequestException("Invalid configuration PIN");
        }
    }

    @POST
    @Path("createRequestID")
    public RequestId createRequestID(CertificateSetupRequest request) throws Exception {

        logger.info("CAInstallerService: Creating request ID");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            CAEngine engine = CAEngine.getInstance();
            CertRequestRepository requestRepository = engine.getCertRequestRepository();

            RequestId requestID = requestRepository.createRequestID();
            logger.info("CAInstallerService: - request ID: " + requestID.toHexString());

            return requestID;

        } catch (Throwable e) {
            logger.error("Unable to create request ID: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("createCertID")
    public CertId createCertID(CertificateSetupRequest request) throws Exception {

        logger.info("CAInstallerService: Creating cert ID");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            CAEngine engine = CAEngine.getInstance();
            CertificateRepository certificateRepository = engine.getCertificateRepository();

            BigInteger serialNumber = certificateRepository.getNextSerialNumber();
            CertId certID = new CertId(serialNumber);

            logger.info("CAInstallerService: - cert ID: " + certID.toHexString());

            return certID;

        } catch (Throwable e) {
            logger.error("Unable to create cert ID: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("createCert")
    public SystemCertData createCert(CertificateSetupRequest request) throws Exception {

        logger.info("CAInstallerService: Creating cert");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            SystemCertData certData = request.getSystemCert();

            RequestId requestID = certData.getRequestID();
            logger.info("CAInstallerService: - request ID: " + requestID.toHexString());

            String certRequestType = certData.getRequestType();
            logger.info("CAInstallerService: - request type: " + certRequestType);

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

            logger.info("CAInstallerService: - subject: " + subjectName);

            CertId certID = certData.getCertID();
            logger.info("CAInstallerService: - cert ID: " + certID.toHexString());

            // cert type is selfsign or local
            String certType = certData.getType();
            logger.info("CAInstallerService: - cert type: " + certType);

            String profileID = certData.getProfile();
            logger.info("CAInstallerService: - profile: " + profileID);

            String keyAlgorithm = certData.getKeyAlgorithm();
            logger.info("CAInstallerService: - key algorithm: " + keyAlgorithm);

            CAEngine engine = CAEngine.getInstance();

            X500Name issuerName;
            PrivateKey signingPrivateKey;

            if (certType.equals("selfsign")) {

                String tokenName = certData.getToken();
                logger.info("CAInstallerService: - token: " + tokenName);
                CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);

                String hexKeyID = certData.getKeyID();
                logger.info("CAInstallerService: - key ID: " + hexKeyID);

                String keyID = hexKeyID;
                if (keyID.startsWith("0x")) keyID = keyID.substring(2);
                if (keyID.length() % 2 == 1) keyID = "0" + keyID;
                PK11PrivKey privateKey = (PK11PrivKey) CryptoUtil.findPrivateKey(
                        token,
                        Hex.decodeHex(keyID));

                if (privateKey == null) {
                    throw new Exception("Private key not found: " + hexKeyID);
                }

                PK11PubKey publicKey = privateKey.getPublicKey();
                KeyPair keyPair = new KeyPair(publicKey, privateKey);

                issuerName = subjectName;
                signingPrivateKey = (PrivateKey) keyPair.getPrivate();

            } else { // certType == local

                CAEngineConfig engineConfig = engine.getConfig();
                CAConfig caConfig = engineConfig.getCAConfig();
                ConfigStore caSigningCfg = caConfig.getSubStore("signing", ConfigStore.class);

                // create CA signing unit
                CASigningUnit signingUnit = new CASigningUnit();
                signingUnit.init(caSigningCfg, null);

                X509CertImpl caCertImpl = signingUnit.getCertImpl();
                CertificateSubjectName certSubjectName = caCertImpl.getSubjectObj();

                // use CA's issuer object to preserve DN encoding
                issuerName = (X500Name) certSubjectName.get(CertificateIssuerName.DN_NAME);
                signingPrivateKey = signingUnit.getPrivateKey();
            }

            logger.info("CAInstallerService: - issuer: " + issuerName);

            String signingAlgorithm = certData.getSigningAlgorithm();
            logger.info("CAInstallerService: - signing algorithm: " + signingAlgorithm);

            CertificateIssuerName certIssuerName = new CertificateIssuerName(issuerName);
            CertificateExtensions extensions = new CertificateExtensions();

            String instanceRoot = cs.getInstanceDir();
            String configurationRoot = cs.getString("configurationRoot");
            String profilePath = instanceRoot + configurationRoot + profileID;

            logger.info("CAInstallerService: Loading " + profilePath);
            ConfigStore profileConfig = engine.loadConfigStore(profilePath);
            BootstrapProfile profile = new BootstrapProfile(profileConfig);

            Date date = new Date();
            X509CertInfo certInfo = CryptoUtil.createX509CertInfo(
                    x509key,
                    certID.toBigInteger(),
                    certIssuerName,
                    subjectName,
                    date,
                    date,
                    keyAlgorithm,
                    extensions);

            logger.info("CAInstallerService: Cert info:\n" + certInfo);

            CertRequestRepository requestRepository = engine.getCertRequestRepository();
            Request requestRecord = requestRepository.readRequest(requestID);

            profile.populate(requestRecord, certInfo);
            requestRepository.updateRequest(requestRecord);

            X509CertImpl certImpl = CryptoUtil.signCert(
                    signingPrivateKey,
                    certInfo,
                    signingAlgorithm);

            byte[] binCert = certImpl.getEncoded();
            certData.setCert(CryptoUtil.base64Encode(binCert));

            return certData;

        } catch (Throwable e) {
            logger.error("Unable to create cert: " + e.getMessage(), e);
            throw e;
        }
    }

    @POST
    @Path("initSubsystem")
    public void initSubsystem(CertificateSetupRequest request) throws Exception {

        logger.info("CAInstallerService: Initializing subsystem");

        try {
            validatePin(request.getPin());

            if (csState.equals("1")) {
                throw new BadRequestException("System already configured");
            }

            CAEngine engine = CAEngine.getInstance();
            CAEngineConfig engineConfig = engine.getConfig();

            CertificateAuthority ca = engine.getCA();
            ca.setConfig(engineConfig.getCAConfig());
            ca.initCertSigningUnit();

        } catch (Throwable e) {
            logger.error("Unable to initialize subsystem: " + e.getMessage(), e);
            throw e;
        }
    }
}
