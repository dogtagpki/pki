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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;
import java.util.Enumeration;
import java.util.StringTokenizer;

import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebInitParam;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.server.ca.CAEngine;
import org.mozilla.jss.crypto.PQGParams;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
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
import com.netscape.certsrv.security.KeyCertData;
import com.netscape.certsrv.security.SigningUnit;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.cert.CrossCertPairSubsystem;
import com.netscape.cmscore.dbs.CertRecord;
import com.netscape.cmscore.dbs.CertificateRepository;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * A class representing an administration servlet. This
 * servlet is responsible to serve Certificate Server
 * level administrative operations such as configuration
 * parameter updates.
 */
@WebServlet(
        name = "caserver",
        urlPatterns = "/server",
        initParams = {
                @WebInitParam(name="ID",       value="caserver"),
                @WebInitParam(name="AuthzMgr", value="BasicAclAuthz")
        }
)
public class CACMSAdminServlet extends CMSAdminServlet {

    @Override
    public boolean isSubsystemInstalled(String subsystem) {
        return subsystem.equals("ca");
    }

    @Override
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

    @Override
    void readSubsystem(NameValuePairs params) {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();

        params.put(ca.getId(), Constants.PR_CA_INSTANCE);
    }

    @Override
    String getCANickname() {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        SigningUnit signingUnit = ca.getSigningUnit();

        return signingUnit.getNickname();
    }

    @Override
    String getCANewnickname() throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        SigningUnit signingUnit = ca.getSigningUnit();

        return signingUnit.getNewNickName();
    }

    @Override
    void setCANewnickname(String tokenName, String nickname) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        SigningUnit signingUnit = ca.getSigningUnit();

        if (CryptoUtil.isInternalToken(tokenName)) {
            signingUnit.setNewNickName(nickname);

        } else if (tokenName.equals("") && nickname.equals("")) {
            signingUnit.setNewNickName("");

        } else {
            signingUnit.setNewNickName(tokenName + ":" + nickname);
        }
    }

    @Override
    String getOCSPNickname() {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        SigningUnit signingUnit = ca.getOCSPSigningUnit();

        return signingUnit.getNickname();
    }

    String getOCSPNewnickname() throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        SigningUnit signingUnit = ca.getOCSPSigningUnit();

        return signingUnit.getNewNickName();
    }

    @Override
    void setOCSPNewnickname(String tokenName, String nickname) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        CertificateAuthority ca = engine.getCA();
        SigningUnit signingUnit = ca.getOCSPSigningUnit();

        if (CryptoUtil.isInternalToken(tokenName)) {
            signingUnit.setNewNickName(nickname);

        } else if (tokenName.equals("") && nickname.equals("")) {
            signingUnit.setNewNickName("");

        } else {
            signingUnit.setNewNickName(tokenName + ":" + nickname);
        }
    }

    @Override
    public void modifyCACert(HttpServletRequest request, String value) throws EBaseException {

        CAEngine engine = CAEngine.getInstance();
        Auditor auditor = engine.getAuditor();
        String auditSubjectID = auditSubjectID();

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

            auditor.log(auditMessage);

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

            auditor.log(auditMessage);

            throw new EBaseException(CMS.getLogMessage("BASE_NOT_CA_CERT"));
        }

        signingUnit.updateConfig(nickName, tokenName);
    }

    @Override
    public void modifyServerCert(String nickname) throws EBaseException {
        modifyCAGatewayCert(nickname);
    }

    @Override
    public void modifyCAGatewayCert(String nickname) {

        CAEngine engine = CAEngine.getInstance();
        engine.setServerCertNickname(nickname);

        /*
         HTTPSubsystem caGateway = ca.getHTTPSubsystem();
         HTTPService httpsService = caGateway.getHttpsService();
         httpsService.setNickName(nickName);
         */
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
    @Override
    public void issueImportCert(
            HttpServletRequest request,
            HttpServletResponse response
            ) throws ServletException, IOException, EBaseException {

        CAEngine engine = CAEngine.getInstance();
        Auditor auditor = engine.getAuditor();

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
                auditor.log(new ConfigTrustedPublicKeyEvent(
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
                auditor.log(new ConfigTrustedPublicKeyEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(request)));
                throw new EBaseException(CMS.getLogMessage("BASE_CERT_NOT_FOUND"));
            }

            // renew ca, use old issuer?
            properties.setIssuerName(jssSubsystem.getCertSubjectName(oldcatokenname, canicknameWithoutTokenName));

            if (nickname.equals("")) {
                auditor.log(new ConfigTrustedPublicKeyEvent(
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
                    modifyCAGatewayCert(nickname);

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

            auditor.log(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(request)));

            mConfig.commit(true);
            sendResponse(SUCCESS, null, null, response);

        } catch (EBaseException e) {
            logger.error("CACMSAdminServlet: " + e.getMessage());

            auditor.log(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(request)));

            throw e;

        } catch (IOException e) {
            logger.error("CACMSAdminServlet: " + e.getMessage());

            auditor.log(new ConfigTrustedPublicKeyEvent(
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
        //     auditor.log(auditMessage);
        //
        //     throw e;
        }
    }

    @Override
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

    @Override
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

    @Override
    protected void importXCert(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {

        CAEngine engine = CAEngine.getInstance();
        Auditor auditor = engine.getAuditor();

        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String b64Cert = "";
            String pathname = "";
            String serverRoot = "";
            String serverID = "";
            String certpath = "";

            Enumeration<String> names = req.getParameterNames();
            NameValuePairs results = new NameValuePairs();

            while (names.hasMoreElements()) {
                String key = names.nextElement();
                String value = req.getParameter(key);

                // really should be PR_CERT_CONTENT
                if (key.equals(Constants.PR_PKCS10)) {
                    b64Cert = value;
                } else if (key.equals("pathname")) {
                    pathname = value;
                } else if (key.equals(Constants.PR_SERVER_ROOT)) {
                    serverRoot = value;
                } else if (key.equals(Constants.PR_SERVER_ID)) {
                    serverID = value;
                } else if (key.equals(Constants.PR_CERT_FILEPATH)) {
                    certpath = value;
                }
            }

            try {
                if (b64Cert == null || b64Cert.equals("")) {
                    if (certpath == null || certpath.equals("")) {

                        auditor.log(new ConfigTrustedPublicKeyEvent(
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req)));

                        EBaseException ex = new EBaseException(CMS.getLogMessage("BASE_INVALID_FILE_PATH"));

                        throw ex;
                    }

                    FileInputStream in = new FileInputStream(certpath);
                    BufferedReader d = new BufferedReader(new InputStreamReader(in));
                    String content = "";

                    b64Cert = "";
                    StringBuffer sb = new StringBuffer();
                    while ((content = d.readLine()) != null) {
                        sb.append(content);
                        sb.append("\n");
                    }
                    b64Cert = sb.toString();
                    d.close();
                    b64Cert = b64Cert.substring(0, b64Cert.length() - 1);
                }

            } catch (IOException e) {

                auditor.log(new ConfigTrustedPublicKeyEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                throw new EBaseException(CMS.getLogMessage("BASE_OPEN_FILE_FAILED"));
            }

            logger.debug("CACMSAdminServlet: got b64Cert");
            b64Cert = Cert.stripBrackets(b64Cert.trim());

            // Base64 decode cert
            byte[] bCert = null;

            try {
                bCert = Utils.base64decode(b64Cert);

            } catch (Exception e) {
                logger.warn("CACMSAdminServlet: exception: " + e);
            }

            pathname = serverRoot + File.separator + serverID
                     + File.separator + "config" + File.separator + pathname;

            CrossCertPairSubsystem ccps = (CrossCertPairSubsystem) engine.getSubsystem(CrossCertPairSubsystem.ID);

            try {
                //this will import into internal ldap crossCerts entry
                ccps.importCert(bCert);

            } catch (Exception e) {

                auditor.log(new ConfigTrustedPublicKeyEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(1, "xcert importing failure:" + e, null, resp);
                return;
            }

            try {
                // this will publish all of the cross cert pairs from internal
                // db to publishing directory, if turned on
                ccps.publishCertPairs();

            } catch (EBaseException e) {

                auditor.log(new ConfigTrustedPublicKeyEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                sendResponse(1, "xcerts publishing failure:" + e, null, resp);
                return;
            }

            JssSubsystem jssSubsystem = engine.getJSSSubsystem();
            String content = jssSubsystem.getCertPrettyPrint(b64Cert, super.getLocale(req));

            results.put(Constants.PR_NICKNAME, "FBCA cross-signed cert");
            results.put(Constants.PR_CERT_CONTENT, content);

            auditor.log(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req)));

            sendResponse(SUCCESS, null, results, resp);

        } catch (EBaseException e) {

            auditor.log(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw e;

        } catch (IOException e) {

            auditor.log(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw e;

        // } catch (ServletException e) {
        //
        //     // store a message in the signed audit log file
        //     auditMessage = CMS.getLogMessage(
        //                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
        //                        auditSubjectID,
        //                        ILogger.FAILURE,
        //                        auditParams(req) );
        //
        //     auditor.log(auditMessage);
        //
        //     // rethrow the specific exception to be handled later
        //     throw e;
        }
    }
}
