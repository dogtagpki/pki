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
package com.netscape.cms.servlet.admin;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;
import java.util.Enumeration;
import java.util.StringTokenizer;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.crypto.PQGParams;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.x509.BasicConstraintsExtension;
import org.mozilla.jss.netscape.security.x509.CertificateExtensions;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;
import org.mozilla.jss.netscape.security.x509.X509CertInfo;

import com.netscape.ca.CertificateAuthority;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigTrustedPublicKeyEvent;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.security.KeyCertData;
import com.netscape.certsrv.security.SigningUnit;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * A class representing an administration servlet. This
 * servlet is responsible to serve Certificate Server
 * level administrative operations such as configuration
 * parameter updates.
 */
public class CACMSAdminServlet extends CMSAdminServlet {

    public boolean isSubsystemInstalled(String subsystem) {
        return subsystem.equals("ca");
    }

    public void readEncryption(NameValuePairs params) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        CertificateAuthority ca = engine.getCA();
        SigningUnit signingUnit = ca.getSigningUnit();

        String caTokenName = signingUnit.getTokenName();
        if (caTokenName.equals(jssSubsystem.getInternalTokenName())) {
            caTokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
        }

        String caNickName = signingUnit.getNickname();

        // params.add(Constants.PR_CERT_CA, caTokenName + "," + caNickName);
        params.put(Constants.PR_CERT_CA, getCertNickname(caNickName));
    }

    public void modifyCACert(HttpServletRequest request, String value) throws EBaseException {

        String auditSubjectID = auditSubjectID();

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        SigningUnit signingUnit = ca.getSigningUnit();

        StringTokenizer tokenizer = new StringTokenizer(value, ",");

        if (tokenizer.countTokens() != 2) {
            // store a message in the signed audit log file
            String auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_ENCRYPTION,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(request));

            audit(auditMessage);

            throw new EBaseException(CMS.getLogMessage("BASE_INVALID_UI_INFO"));
        }

        String tokenName = (String) tokenizer.nextElement();
        String nickName = (String) tokenizer.nextElement();

        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        if (CryptoUtil.isInternalToken(tokenName)) {
            tokenName = jssSubsystem.getInternalTokenName();
        } else {
            nickName = tokenName + ":" + nickName;
        }

        boolean isCACert = jssSubsystem.isCACert(nickName);
        if (!isCACert) {
            // store a message in the signed audit log file
            String auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_ENCRYPTION,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(request));

            audit(auditMessage);

            throw new EBaseException(CMS.getLogMessage("BASE_NOT_CA_CERT"));
        }

        signingUnit.updateConfig(nickName, tokenName);
    }

    public void modifyServerCert(String nickname) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        modifyCAGatewayCert(ca, nickname);
    }

    public void updateCASignature(
            String nickname,
            KeyCertData properties,
            JssSubsystem jssSubsystem
            ) throws EBaseException {

        String alg = jssSubsystem.getSignatureAlgorithm(nickname);
        SignatureAlgorithm sigAlg = Cert.mapAlgorithmToJss(alg);

        properties.setSignatureAlgorithm(sigAlg);
        properties.setAlgorithmId(jssSubsystem.getAlgorithmId(alg, mConfig));
    }

    /**
     * Issue import certificate
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY used when
     * "Certificate Setup Wizard" is used to import CA certs into the certificate database
     * </ul>
     *
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException failed to issue an import certificate
     */
    public void issueImportCert(
            HttpServletRequest request,
            HttpServletResponse response
            ) throws ServletException, IOException, EBaseException {

        CAEngine engine = CAEngine.getInstance();
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String tokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
            String keyType = "RSA";
            String newtokenname = null;
            KeyCertData properties = new KeyCertData();

            Enumeration<String> paramNames = request.getParameterNames();
            while (paramNames.hasMoreElements()) {

                String name = paramNames.nextElement();
                String value = request.getParameter(name);

                if (name.equals("pathname")) {
                    continue;
                }

                if (name.equals(Constants.PR_TOKEN_NAME)) {
                    newtokenname = value;
                }

                properties.put(name, value);
            }

            String certType = (String) properties.get(Constants.RS_ID);

            JssSubsystem jssSubsystem = engine.getJSSSubsystem();
            CertificateAuthority ca = engine.getCA();
            SigningUnit signingUnit = ca.getSigningUnit();

            // this is the old nick name
            String nickname = getNickname(certType);
            String nicknameWithoutTokenName = "";
            String oldcatokenname = signingUnit.getTokenName();
            String canickname = getNickname(Constants.PR_CA_SIGNING_CERT);
            String canicknameWithoutTokenName = "";

            int index = nickname.indexOf(":");
            String oldtokenname = null;

            if (index == -1) {
                nicknameWithoutTokenName = nickname;
                oldtokenname = CryptoUtil.INTERNAL_TOKEN_NAME;

            } else if (index > 0 && (index < (nickname.length() - 1))) {
                nicknameWithoutTokenName = nickname.substring(index + 1);
                oldtokenname = nickname.substring(0, index);

            } else {
                audit(new ConfigTrustedPublicKeyEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(request)));
                throw new EBaseException(CMS.getLogMessage("BASE_CERT_NOT_FOUND"));
            }

            if (newtokenname == null) {
                newtokenname = oldtokenname;
            }

            index = canickname.indexOf(":");

            if (index == -1) {
                canicknameWithoutTokenName = canickname;

            } else if (index > 0 && (index < (canickname.length() - 1))) {
                canicknameWithoutTokenName = canickname.substring(index + 1);

            } else {
                audit(new ConfigTrustedPublicKeyEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(request)));
                throw new EBaseException(CMS.getLogMessage("BASE_CERT_NOT_FOUND"));
            }

            // renew ca, use old issuer?
            properties.setIssuerName(jssSubsystem.getCertSubjectName(oldcatokenname, canicknameWithoutTokenName));

            if (nickname.equals("")) {
                audit(new ConfigTrustedPublicKeyEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(request)));
                throw new EBaseException(CMS.getLogMessage("BASE_CERT_NOT_FOUND"));
            }

            // set to old nickname?
            properties.setCertNickname(nickname);

            if (!certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                CertificateExtensions exts = jssSubsystem.getExtensions(oldcatokenname, canicknameWithoutTokenName);
                properties.setCAExtensions(exts);
            }

            String defaultSigningAlg = null;
            String defaultOCSPSigningAlg = null;

            if (properties.getHashType() != null) {
                if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                    defaultSigningAlg = properties.getHashType();
                }

                if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
                    defaultOCSPSigningAlg = properties.getHashType();
                }
            }

            KeyPair pair = null;
            KeyPair caKeyPair = null;

            // create a new CA certificate or ssl server cert
            if (properties.getKeyCurveName() != null) { //new ECC
                logger.info("CACMSAdminServlet: Generating ECC keys");
                pair = jssSubsystem.getECCKeyPair(properties);
                if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                    caKeyPair = pair;
                }

            } else if (properties.getKeyLength() != null) { //new RSA or DSA
                keyType = properties.getKeyType();
                String keyLen = properties.getKeyLength();

                if (keyType.equals("DSA")) {
                    @SuppressWarnings("unused")
                    PQGParams pqgParams = jssSubsystem.getCAPQG(Integer.parseInt(keyLen), mConfig); // check for errors
                    // properties.put(Constants.PR_PQGPARAMS, pqgParams);
                }

                pair = jssSubsystem.getKeyPair(properties);

                if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                    caKeyPair = pair;
                }
                // renew the CA certificate or ssl server cert

            } else {
                pair = jssSubsystem.getKeyPair(nickname);
                // should get it from the CA signing certificate
                if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                    updateCASignature(nickname, properties, jssSubsystem);
                    caKeyPair = pair;
                    defaultSigningAlg = signingUnit.getDefaultAlgorithm();
                }

                /*
                String alg = jssSubSystem.getSignatureAlgorithm(nickname);
                SignatureAlgorithm sigAlg = SigningUnit.mapAlgorithmToJss(alg);
                properties.setSignatureAlgorithm(sigAlg);
                properties.setAlgorithmId(
                jssSubSystem.getAlgorithmId(alg, mConfig));
                */
            }

            String alg = properties.getSignedBy();
            if (!certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                caKeyPair = jssSubsystem.getKeyPair(canickname);
                updateCASignature(canickname, properties, jssSubsystem);

            } else if (alg != null) {
                // self signed CA signing cert, new keys
                // value provided for signedBy
                SignatureAlgorithm sigAlg = Cert.mapAlgorithmToJss(alg);
                properties.setSignatureAlgorithm(sigAlg);
                properties.setAlgorithmId(jssSubsystem.getAlgorithmId(alg, mConfig));
            }

            if (pair == null) {
                logger.warn("CACMSAdminServlet: Missing key pair");
            }

            CertificateRepository repository = engine.getCertificateRepository();
            BigInteger nextSerialNo = repository.getNextSerialNumber();

            properties.setSerialNumber(nextSerialNo);
            properties.setKeyPair(pair);
            properties.setConfigFile(mConfig);
            // properties.put(Constants.PR_CA_KEYPAIR, pair);
            properties.put(Constants.PR_CA_KEYPAIR, caKeyPair);

            X509CertImpl signedCert = jssSubsystem.getSignedCert(properties, certType, caKeyPair.getPrivate());

            if (signedCert == null) {
                logger.warn("CACMSAdminServlet: Missing signed certificate");
            }

            /* bug 600124
            try {
                jssSubSystem.deleteTokenCertificate(nickname, pathname);
            } catch (Throwable e) {
                // skip it
            }
            */

            boolean nicknameChanged = false;

            // import cert with nickname without token name?
            // jss adds the token prefix!!!
            // logger.info("CACMSAdminServlet: Import as alias " +  nicknameWithoutTokenName);
            try {
                logger.info("CACMSAdminServlet: Importing cert: " + nicknameWithoutTokenName);
                jssSubsystem.importCert(signedCert, nicknameWithoutTokenName, certType);

            } catch (EBaseException e) {

                logger.warn("CACMSAdminServlet: Unable to import " + nicknameWithoutTokenName + ": " + e.getMessage());

                // if it fails, let use a different nickname to try
                Date now = new Date();
                String newNickname = nicknameWithoutTokenName + "-" + now.getTime();

                logger.info("CACMSAdminServlet: Importing cert with nickname: " + newNickname);
                jssSubsystem.importCert(signedCert, newNickname, certType);

                nicknameWithoutTokenName = newNickname;
                nicknameChanged = true;

                if (tokenName.equals(CryptoUtil.INTERNAL_TOKEN_NAME)) {
                    nickname = newNickname;
                } else {
                    nickname = tokenName + ":" + newNickname;
                }
            }

            CertRecord certRecord = new CertRecord(signedCert.getSerialNumber(), signedCert, null);
            repository.addCertificateRecord(certRecord);

            if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                try {
                    X509CertInfo certInfo = (X509CertInfo) signedCert.get(X509CertImpl.NAME + "." + X509CertImpl.INFO);
                    CertificateExtensions extensions = (CertificateExtensions) certInfo.get(X509CertInfo.EXTENSIONS);

                    if (extensions != null) {
                        BasicConstraintsExtension basic = (BasicConstraintsExtension) extensions.get(BasicConstraintsExtension.NAME);

                        if (basic == null) {
                            logger.warn(CMS.getLogMessage("ADMIN_SRVLT_BASIC_CONSTRAIN_NULL"));

                        } else {
                            Integer pathlen = (Integer) basic.get(BasicConstraintsExtension.PATH_LEN);
                            int num = pathlen.intValue();

                            if (num == 0) {
                                ca.setBasicConstraintMaxLen(num);
                            } else if (num > 0) {
                                num = num - 1;
                                ca.setBasicConstraintMaxLen(num);
                            }
                        }

                    } else {
                        logger.warn(CMS.getLogMessage("ADMIN_SRVLT_CERT_NO_EXT"));
                    }

                } catch (Exception e) {
                    logger.warn("CACMSAdminServlet: " + e.getMessage(), e);
                }
            }

            logger.debug("CACMSAdminServlet: old token:" + oldtokenname);
            logger.debug("CACMSAdminServlet: new token:" + newtokenname);
            logger.debug("CACMSAdminServlet: nickname:" + nickname);

            if ((newtokenname != null && !newtokenname.equals(oldtokenname)) || nicknameChanged) {

                if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                    if (newtokenname.equals(CryptoUtil.INTERNAL_TOKEN_NAME)) {
                        signingUnit.updateConfig(nicknameWithoutTokenName, newtokenname);
                    } else {
                        signingUnit.updateConfig(newtokenname + ":" + nicknameWithoutTokenName, newtokenname);
                    }

                } else if (certType.equals(Constants.PR_SERVER_CERT)) {
                    if (newtokenname.equals(CryptoUtil.INTERNAL_TOKEN_NAME)) {
                        nickname = nicknameWithoutTokenName;
                    } else {
                        nickname = newtokenname + ":" + nicknameWithoutTokenName;
                    }

                    // setRADMNewnickname("", "");
                    // modifyRADMCert(nickname);
                    modifyAgentGatewayCert(nickname);

                    if (isSubsystemInstalled("ra")) {
                        IRegistrationAuthority ra = (IRegistrationAuthority) engine.getSubsystem(IRegistrationAuthority.ID);
                        modifyEEGatewayCert(ra, nickname);
                    }

                    if (isSubsystemInstalled("ca")) {
                        modifyCAGatewayCert(ca, nickname);
                    }

                } else if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
                    if (newtokenname.equals(CryptoUtil.INTERNAL_TOKEN_NAME)) {
                        nickname = nicknameWithoutTokenName;
                    } else {
                        nickname = newtokenname + ":" + nicknameWithoutTokenName;
                    }

                    modifyRADMCert(nickname);

                } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
                    if (ca != null) {
                        SigningUnit ocspSigningUnit = ca.getOCSPSigningUnit();

                        if (newtokenname.equals(CryptoUtil.INTERNAL_TOKEN_NAME)) {
                            ocspSigningUnit.updateConfig(nicknameWithoutTokenName, newtokenname);
                        } else {
                            ocspSigningUnit.updateConfig(newtokenname + ":" + nicknameWithoutTokenName, newtokenname);
                        }
                    }
                }
            }

            // set signing algorithms if needed
            if (certType.equals(Constants.PR_CA_SIGNING_CERT))
                signingUnit.setDefaultAlgorithm(defaultSigningAlg);

            if (defaultOCSPSigningAlg != null) {
                SigningUnit ocspSigningUnit = ca.getOCSPSigningUnit();
                ocspSigningUnit.setDefaultAlgorithm(defaultOCSPSigningAlg);
            }

            properties.clear();
            properties = null;

            audit(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(request)));

            mConfig.commit(true);
            sendResponse(SUCCESS, null, null, response);

        } catch (EBaseException e) {
            logger.error("CACMSAdminServlet: " + e.getMessage());

            audit(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(request)));

            throw e;

        } catch (IOException e) {
            logger.error("CACMSAdminServlet: " + e.getMessage());

            audit(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(request)));

            throw e;

        // } catch(ServletException e) {
        //     // store a message in the signed audit log file
        //     auditMessage = CMS.getLogMessage(
        //                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
        //                        auditSubjectID,
        //                        ILogger.FAILURE,
        //                        auditParams(req));
        //
        //     audit(auditMessage);
        //
        //     throw e;
        }
    }

    public void installCASigningCert(
            String fullName,
            String nickname,
            String tokenName
            ) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();

        CertificateAuthority ca = engine.getCA();
        SigningUnit signingUnit = ca.getSigningUnit();

        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        String signatureAlg = jssSubsystem.getSignatureAlgorithm(fullName);
        signingUnit.setDefaultAlgorithm(signatureAlg);

        setCANewnickname("", "");

        try {
            CertificateExtensions extensions = null;

            if (fullName.equals(nickname)) {
                signingUnit.updateConfig(fullName, CryptoUtil.INTERNAL_TOKEN_NAME);
                extensions = jssSubsystem.getExtensions(CryptoUtil.INTERNAL_TOKEN_NAME, fullName);
            } else {
                signingUnit.updateConfig(fullName, tokenName);
                extensions = jssSubsystem.getExtensions(tokenName, nickname);
            }

            if (extensions != null) {
                BasicConstraintsExtension basic = (BasicConstraintsExtension) extensions.get(BasicConstraintsExtension.NAME);

                if (basic == null) {
                    logger.warn(CMS.getLogMessage("ADMIN_SRVLT_BASIC_CONSTRAIN_NULL"));

                } else {
                    Integer pathlen = (Integer) basic.get(BasicConstraintsExtension.PATH_LEN);
                    int num = pathlen.intValue();

                    if (num == 0) {
                        ca.setBasicConstraintMaxLen(num);
                    } else if (num > 0) {
                        num = num - 1;
                        ca.setBasicConstraintMaxLen(num);
                    }
                }

            } else {
                logger.warn(CMS.getLogMessage("ADMIN_SRVLT_CERT_NO_EXT"));
            }

        } catch (Exception e) {
            logger.warn("CACMSAdminServlet: " + e.toString());
        }
    }

    public void installOCSPSigningCert(
            String fullName,
            String nickname,
            String tokenName
            ) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        setOCSPNewnickname("", "");

        SigningUnit signingUnit = ca.getOCSPSigningUnit();

        if (fullName.equals(nickname)) {
            signingUnit.updateConfig(fullName, CryptoUtil.INTERNAL_TOKEN_NAME);
        } else {
            signingUnit.updateConfig(fullName, tokenName);
        }
    }
}
