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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.BasicConstraintsExtension;
import netscape.security.x509.CertificateExtensions;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509CertInfo;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PQGParams;
import org.mozilla.jss.crypto.SignatureAlgorithm;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.util.ConsolePasswordCallback;
import org.mozilla.jss.util.PasswordCallback;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IConfigStore;
import com.netscape.certsrv.base.ISubsystem;
import com.netscape.certsrv.ca.ICertificateAuthority;
import com.netscape.certsrv.cert.ICrossCertPairSubsystem;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.dbs.certdb.ICertRecord;
import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.ocsp.IOCSPAuthority;
import com.netscape.certsrv.ra.IRegistrationAuthority;
import com.netscape.certsrv.security.ICryptoSubsystem;
import com.netscape.certsrv.security.ISigningUnit;
import com.netscape.certsrv.security.KeyCertData;
import com.netscape.certsrv.selftests.EMissingSelfTestException;
import com.netscape.certsrv.selftests.ESelfTestException;
import com.netscape.certsrv.selftests.ISelfTest;
import com.netscape.certsrv.selftests.ISelfTestSubsystem;
import com.netscape.certsrv.tks.ITKSAuthority;
import com.netscape.cmsutil.util.Cert;
import com.netscape.cmsutil.util.Utils;
import com.netscape.symkey.SessionKey;

/**
 * A class representings an administration servlet. This
 * servlet is responsible to serve Certificate Server
 * level administrative operations such as configuration
 * parameter updates.
 *
 * @version $Revision$, $Date$
 */
public final class CMSAdminServlet extends AdminServlet {

    /**
     *
     */
    private static final long serialVersionUID = 714370238027440050L;
    private final static String INFO = "CMSAdminServlet";
    private final static String BEGIN_HEADER = "-----BEGIN CERTIFICATE-----";
    private final static String END_HEADER = "-----END CERTIFICATE-----";

    private final static String PROP_DB = "dbs";
    private final static String PROP_SMTP = "smtp";
    private final static String PROP_INTERNAL_DB = "internaldb";

    private ILogger mSignedAuditLogger = CMS.getSignedAuditLogger();
    private final static byte EOL[] = { Character.LINE_SEPARATOR };
    private final static String LOGGING_SIGNED_AUDIT_CONFIG_ENCRYPTION =
            "LOGGING_SIGNED_AUDIT_CONFIG_ENCRYPTION_3";
    private final static String LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY =
            "LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY_3";
    private final static String LOGGING_SIGNED_AUDIT_KEY_GEN_ASYMMETRIC =
            "LOGGING_SIGNED_AUDIT_KEY_GEN_ASYMMETRIC_3";
    private final static String LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION =
            "LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION_2";
    private final static String LOGGING_SIGNED_AUDIT_CIMC_CERT_VERIFICATION =
            "LOGGING_SIGNED_AUDIT_CIMC_CERT_VERIFICATION_3";

    // CMS must be instantiated before this admin servlet.

    /**
     * Constructs CA servlet.
     */
    public CMSAdminServlet() {
        super();
    }

    /**
     * Initializes this servlet.
     */
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Serves HTTP request.
     */
    public void service(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        super.service(req, resp);
        try {
            super.authenticate(req);
        } catch (IOException e) {
            sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHS_FAILED"),
                    null, resp);
            return;
        }

        String scope = req.getParameter(Constants.OP_SCOPE);
        String op = req.getParameter(Constants.OP_TYPE);

        try {
            AUTHZ_RES_NAME = "certServer.general.configuration";
            if (scope.equals(ScopeDef.SC_PLATFORM)) {
                mOp = "read";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                getEnv(req, resp);
                return;
            }
            if (op.equals(OpDef.OP_READ)) {
                mOp = "read";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_LDAP))
                    getDBConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_SMTP))
                    readSMTPConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_STAT))
                    readStat(req, resp);
                else if (scope.equals(ScopeDef.SC_ENCRYPTION))
                    readEncryption(req, resp);
                else if (scope.equals(ScopeDef.SC_TOKEN))
                    getAllTokenNames(req, resp);
                else if (scope.equals(ScopeDef.SC_SUBJECT_NAME))
                    getSubjectName(req, resp);
                else if (scope.equals(ScopeDef.SC_GET_NICKNAMES))
                    getAllNicknames(req, resp);
                else if (scope.equals(ScopeDef.SC_CERT_PRETTY_PRINT))
                    getCertPrettyPrint(req, resp);
            } else if (op.equals(OpDef.OP_MODIFY)) {
                mOp = "modify";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_LDAP))
                    setDBConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_SMTP))
                    modifySMTPConfig(req, resp);
                else if (scope.equals(ScopeDef.SC_TASKS))
                    performTasks(req, resp);
                else if (scope.equals(ScopeDef.SC_ENCRYPTION))
                    modifyEncryption(req, resp);
                else if (scope.equals(ScopeDef.SC_ISSUE_IMPORT_CERT))
                    issueImportCert(req, resp);
                else if (scope.equals(ScopeDef.SC_INSTALL_CERT))
                    installCert(req, resp);
                else if (scope.equals(ScopeDef.SC_IMPORT_CROSS_CERT))
                    importXCert(req, resp);
                else if (scope.equals(ScopeDef.SC_DELETE_CERTS))
                    deleteCerts(req, resp);
                else if (scope.equals(ScopeDef.SC_TRUST))
                    trustCACert(req, resp);
                else if (scope.equals(ScopeDef.SC_TOKEN_LOGON))
                    loggedInToken(req, resp);
                else if (scope.equals(ScopeDef.SC_ROOTCERT_TRUSTBIT))
                    setRootCertTrust(req, resp);
            } else if (op.equals(OpDef.OP_SEARCH)) {
                mOp = "read";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_SUBSYSTEM))
                    readSubsystem(req, resp);
                else if (scope.equals(ScopeDef.SC_CA_CERTLIST))
                    getCACerts(req, resp);
                else if (scope.equals(ScopeDef.SC_ALL_CERTLIST))
                    getAllCertsManage(req, resp);
                else if (scope.equals(ScopeDef.SC_USERCERTSLIST))
                    getUserCerts(req, resp);
                else if (scope.equals(ScopeDef.SC_TKSKEYSLIST))
                    getTKSKeys(req, resp);
                else if (scope.equals(ScopeDef.SC_TOKEN))
                    getAllTokenNames(req, resp);
                else if (scope.equals(ScopeDef.SC_ROOTCERTSLIST))
                    getRootCerts(req, resp);
            } else if (op.equals(OpDef.OP_DELETE)) {
                mOp = "delete";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_ROOTCERTSLIST)) {
                    deleteRootCert(req, resp);
                } else if (scope.equals(ScopeDef.SC_USERCERTSLIST)) {
                    deleteUserCert(req, resp);
                }
            } else if (op.equals(OpDef.OP_PROCESS)) {
                mOp = "modify";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_CERT_REQUEST))
                    getCertRequest(req, resp);
                else if (scope.equals(ScopeDef.SC_SUBJECT_NAME))
                    processSubjectName(req, resp);
                else if (scope.equals(ScopeDef.SC_CERTINFO))
                    getCertInfo(req, resp);
                else if (scope.equals(ScopeDef.SC_CERT_PRETTY_PRINT))
                    getCertPrettyPrint(req, resp);
                else if (scope.equals(ScopeDef.SC_ROOTCERT_TRUSTBIT))
                    getRootCertTrustBit(req, resp);
                else if (scope.equals(ScopeDef.SC_TOKEN_STATUS))
                    checkTokenStatus(req, resp);
                else if (scope.equals(ScopeDef.SC_SELFTESTS))
                    runSelfTestsOnDemand(req, resp);
                else if (scope.equals(ScopeDef.SC_TKSKEYSLIST))
                    createMasterKey(req, resp);
            } else if (op.equals(OpDef.OP_VALIDATE)) {
                mOp = "modify";
                if ((mToken = super.authorize(req)) == null) {
                    sendResponse(ERROR,
                            CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_AUTHZ_FAILED"),
                            null, resp);
                    return;
                }
                if (scope.equals(ScopeDef.SC_SUBJECT_NAME))
                    validateSubjectName(req, resp);
                else if (scope.equals(ScopeDef.SC_KEY_LENGTH))
                    validateKeyLength(req, resp);
                else if (scope.equals(ScopeDef.SC_CERTIFICATE_EXTENSION))
                    validateCertExtension(req, resp);
                else if (scope.equals(ScopeDef.SC_KEY_CURVENAME))
                    validateCurveName(req, resp);
            }
        } catch (EBaseException e) {
            sendResponse(ERROR, e.toString(getLocale(req)),
                    null, resp);
            return;
        } catch (Exception e) {
            StringWriter sw = new StringWriter();

            e.printStackTrace(new PrintWriter(sw));

            sendResponse(1, "operation failure", null, resp);
            return;
        }
    }

    private void getEnv(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();

        if (File.separator.equals("\\"))
            params.put(Constants.PR_NT, Constants.TRUE);
        else
            params.put(Constants.PR_NT, Constants.FALSE);

        sendResponse(SUCCESS, null, params, resp);
    }

    private void getAllTokenNames(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_TOKEN_LIST, jssSubSystem.getTokenList());

        sendResponse(SUCCESS, null, params, resp);
    }

    private void getAllNicknames(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);

        params.put(Constants.PR_ALL_NICKNAMES, jssSubSystem.getAllCerts());

        sendResponse(SUCCESS, null, params, resp);
    }

    private boolean isSubsystemInstalled(String subsystem) {
        Enumeration<ISubsystem> e = CMS.getSubsystems();

        while (e.hasMoreElements()) {
            ISubsystem sys = e.nextElement();

            //get subsystem type
            if ((sys instanceof IKeyRecoveryAuthority) &&
                    subsystem.equals("kra"))
                return true;
            else if ((sys instanceof IRegistrationAuthority) &&
                    subsystem.equals("ra"))
                return true;
            else if ((sys instanceof ICertificateAuthority) &&
                    subsystem.equals("ca"))
                return true;
            else if ((sys instanceof IOCSPAuthority) &&
                    subsystem.equals("ocsp"))
                return true;
        }

        return false;
    }

    private void readEncryption(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        Enumeration<ISubsystem> e = CMS.getSubsystems();
        boolean isCAInstalled = false;
        boolean isRAInstalled = false;
        boolean isKRAInstalled = false;

        while (e.hasMoreElements()) {
            ISubsystem sys = e.nextElement();

            //get subsystem type
            if (sys instanceof IKeyRecoveryAuthority)
                isKRAInstalled = true;
            else if (sys instanceof IRegistrationAuthority)
                isRAInstalled = true;
            else if (sys instanceof ICertificateAuthority)
                isCAInstalled = true;

        }

        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        String caTokenName = "";

        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_CIPHER_VERSION,
                jssSubSystem.getCipherVersion());
        params.put(Constants.PR_CIPHER_FORTEZZA, jssSubSystem.isCipherFortezza());
        params.put(Constants.PR_CIPHER_PREF, jssSubSystem.getCipherPreferences());

        String tokenList = jssSubSystem.getTokenList();

        String tokenNewList = "";
        StringTokenizer tokenizer = new StringTokenizer(tokenList, ",");

        while (tokenizer.hasMoreElements()) {
            String tokenName = (String) tokenizer.nextElement();
            String certs = jssSubSystem.getCertListWithoutTokenName(tokenName);

            if (certs.equals(""))
                continue;
            if (tokenNewList.equals(""))
                tokenNewList = tokenNewList + tokenName;
            else
                tokenNewList = tokenNewList + "," + tokenName;
            tokenName = escapeString(tokenName);
            params.put(Constants.PR_TOKEN_PREFIX + tokenName, certs);
        }

        params.put(Constants.PR_TOKEN_LIST, tokenNewList);

        if (isCAInstalled) {
            ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_CA);
            ISigningUnit signingUnit = ca.getSigningUnit();

            caTokenName = signingUnit.getTokenName();

            if (caTokenName.equals(jssSubSystem.getInternalTokenName()))
                caTokenName = Constants.PR_INTERNAL_TOKEN;

            String caNickName = signingUnit.getNickname();

            //params.add(Constants.PR_CERT_CA, caTokenName+","+caNickName);
            params.put(Constants.PR_CERT_CA, getCertNickname(caNickName));
        }

        if (isRAInstalled) {
            IRegistrationAuthority ra = (IRegistrationAuthority)
                    CMS.getSubsystem(CMS.SUBSYSTEM_RA);
            String raNickname = ra.getNickname();

            params.put(Constants.PR_CERT_RA, getCertNickname(raNickname));
        }

        if (isKRAInstalled) {
            IKeyRecoveryAuthority kra = (IKeyRecoveryAuthority)
                    CMS.getSubsystem(CMS.SUBSYSTEM_KRA);
            String kraNickname = kra.getNickname();

            params.put(Constants.PR_CERT_TRANS, getCertNickname(kraNickname));
        }

        String nickName = CMS.getServerCertNickname();

        params.put(Constants.PR_CERT_SERVER, getCertNickname(nickName));

        sendResponse(SUCCESS, null, params, resp);
    }

    private String escapeString(String name) {
        StringTokenizer tokenizer = new StringTokenizer(name, " ");
        StringBuffer tokenname = new StringBuffer();

        if (tokenizer.countTokens() == 1)
            return name;
        while (tokenizer.hasMoreElements()) {
            if (tokenizer.countTokens() == 1)
                tokenname.append((String) tokenizer.nextElement());
            else {
                tokenname.append((String) tokenizer.nextElement());
                tokenname.append("%20");
            }
        }

        return tokenname.toString();
    }

    private String getCertNickname(String nickName) {
        if (!nickName.equals("")) {
            StringTokenizer tokenizer = new StringTokenizer(nickName, ":");
            String tokenName = "";

            if (tokenizer.countTokens() > 1) {
                tokenName = (String) tokenizer.nextElement();
            } else {
                tokenName = Constants.PR_INTERNAL_TOKEN;
            }
            return tokenName + "," + ((String) tokenizer.nextElement());
        }
        return "";
    }

    /**
     * Modify encryption configuration
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_ENCRYPTION used when configuring encryption (cert settings and SSL
     * cipher preferences)
     * </ul>
     *
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException failed to modify encryption configuration
     */
    private void modifyEncryption(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            Enumeration<String> enum1 = req.getParameterNames();
            NameValuePairs params = new NameValuePairs();
            ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                    CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);

            jssSubSystem.getInternalTokenName();
            Enumeration<ISubsystem> e = CMS.getSubsystems();
            boolean isCAInstalled = false;
            boolean isRAInstalled = false;
            boolean isKRAInstalled = false;

            while (e.hasMoreElements()) {
                ISubsystem sys = e.nextElement();

                //get subsystem type
                if (sys instanceof IKeyRecoveryAuthority)
                    isKRAInstalled = true;
                else if (sys instanceof IRegistrationAuthority)
                    isRAInstalled = true;
                else if (sys instanceof ICertificateAuthority)
                    isCAInstalled = true;
            }

            ICertificateAuthority ca = null;
            IRegistrationAuthority ra = null;
            IKeyRecoveryAuthority kra = null;

            if (isCAInstalled)
                ca = (ICertificateAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_CA);
            if (isRAInstalled)
                ra = (IRegistrationAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_RA);
            if (isKRAInstalled)
                kra = (IKeyRecoveryAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_KRA);

            boolean isCACert = true;

            while (enum1.hasMoreElements()) {
                String name = enum1.nextElement();
                String val = req.getParameter(name);

                if (name.equals(Constants.PR_CIPHER_PREF)) {
                    jssSubSystem.setCipherPreferences(val);
                } else if (name.equals(Constants.PR_CERT_CA)) {
                    ISigningUnit signingUnit = ca.getSigningUnit();

                    if ((val != null) && (!val.equals(""))) {
                        StringTokenizer tokenizer = new StringTokenizer(val, ",");

                        if (tokenizer.countTokens() != 2) {
                            // store a message in the signed audit log file
                            auditMessage = CMS.getLogMessage(
                                        LOGGING_SIGNED_AUDIT_CONFIG_ENCRYPTION,
                                        auditSubjectID,
                                        ILogger.FAILURE,
                                        auditParams(req));

                            audit(auditMessage);

                            throw new EBaseException(CMS.getLogMessage("BASE_INVALID_UI_INFO"));
                        }

                        String tokenName = (String) tokenizer.nextElement();
                        String nickName = (String) tokenizer.nextElement();

                        if (tokenName.equals(Constants.PR_INTERNAL_TOKEN)) {
                            tokenName = jssSubSystem.getInternalTokenName();
                        } else {
                            nickName = tokenName + ":" + nickName;
                        }

                        isCACert = jssSubSystem.isCACert(nickName);
                        if (isCACert) {
                            signingUnit.updateConfig(nickName, tokenName);
                        } else
                            // store a message in the signed audit log file
                            auditMessage = CMS.getLogMessage(
                                        LOGGING_SIGNED_AUDIT_CONFIG_ENCRYPTION,
                                        auditSubjectID,
                                        ILogger.FAILURE,
                                        auditParams(req));

                        audit(auditMessage);

                        throw new EBaseException(CMS.getLogMessage("BASE_NOT_CA_CERT"));
                    }
                } else if (name.equals(Constants.PR_CERT_RA)) {
                    if ((val != null) && (!val.equals(""))) {
                        String nickName = getCertConfigNickname(val);

                        ra.setNickname(nickName);
                    }
                } else if (name.equals(Constants.PR_CERT_TRANS)) {
                    if ((val != null) && (!val.equals(""))) {
                        String nickName = getCertConfigNickname(val);

                        kra.setNickname(nickName);
                    }
                } else if (name.equals(Constants.PR_CERT_SERVER)) {
                    if ((val != null) && (!val.equals(""))) {
                        String nickName = getCertConfigNickname(val);

                        modifyRADMCert(nickName);
                        modifyAgentGatewayCert(nickName);
                        if (isRAInstalled)
                            modifyEEGatewayCert(ra, nickName);
                        if (isCAInstalled)
                            modifyCAGatewayCert(ca, nickName);
                    }
                }
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ENCRYPTION,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(RESTART, null, params, resp);
            mConfig.commit(true);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ENCRYPTION,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_ENCRYPTION,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_ENCRYPTION,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    private String getCertConfigNickname(String val) throws EBaseException {
        StringTokenizer tokenizer = new StringTokenizer(val, ",");

        if (tokenizer.countTokens() != 2) {
            throw new EBaseException(CMS.getLogMessage("BASE_INVALID_UI_INFO"));
        }
        String tokenName = (String) tokenizer.nextElement();

        if (tokenName.equals(Constants.PR_INTERNAL_TOKEN))
            tokenName = "";
        else
            tokenName = tokenName + ":";
        return (tokenName + (String) tokenizer.nextElement());
    }

    private void modifyRADMCert(String nickName) {
        CMS.setServerCertNickname(nickName);

        /*
         RemoteAdmin raAdmin = (RemoteAdmin)RemoteAdmin.getInstance();
         HTTPService httpsService = raAdmin.getHttpsService();
         httpsService.setNickName(nickName);
         */
    }

    private void modifyAgentGatewayCert(String nickName) {
        CMS.setServerCertNickname(nickName);

        /*
         AgentGateway gateway = (AgentGateway)mReg.get(AgentGateway.ID);
         HTTPService httpsService = gateway.getHttpsService();
         httpsService.setNickName(nickName);
         */
    }

    private void modifyEEGatewayCert(IRegistrationAuthority ra, String nickName) {
        CMS.setServerCertNickname(nickName);

        /*
         HTTPSubsystem eeGateway = ra.getHTTPSubsystem();
         HTTPService httpsService = eeGateway.getHttpsService();
         httpsService.setNickName(nickName);
         */
    }

    private void modifyCAGatewayCert(ICertificateAuthority ca, String nickName) {
        CMS.setServerCertNickname(nickName);

        /*
         HTTPSubsystem caGateway = ca.getHTTPSubsystem();
         HTTPService httpsService = caGateway.getHttpsService();
         httpsService.setNickName(nickName);
         */
    }

    /**
     * Performs Server Tasks: RESTART/STOP operation
     */
    private void performTasks(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String restart = req.getParameter(Constants.PR_SERVER_RESTART);
        String stop = req.getParameter(Constants.PR_SERVER_STOP);
        NameValuePairs params = new NameValuePairs();

        if (restart != null) {
            //XXX Uncommented afetr watchdog is implemented
            sendResponse(SUCCESS, null, params, resp);
            //mServer.restart();
            return;
        }

        if (stop != null) {
            //XXX Send response first then shutdown
            sendResponse(SUCCESS, null, params, resp);
            CMS.shutdown();
            return;
        }

        sendResponse(ERROR, "Unknown operation", null, resp);

    }

    /**
     * Reads subsystems that server has loaded with.
     */
    private void readSubsystem(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        Enumeration<ISubsystem> e = CMS.getSubsystems();

        while (e.hasMoreElements()) {
            String type = "";
            ISubsystem sys = e.nextElement();

            //get subsystem type
            if (sys instanceof IKeyRecoveryAuthority)
                type = Constants.PR_KRA_INSTANCE;
            if (sys instanceof IRegistrationAuthority)
                type = Constants.PR_RA_INSTANCE;
            if (sys instanceof ICertificateAuthority)
                type = Constants.PR_CA_INSTANCE;
            if (sys instanceof IOCSPAuthority)
                type = Constants.PR_OCSP_INSTANCE;
            if (sys instanceof ITKSAuthority)
                type = Constants.PR_TKS_INSTANCE;
            if (!type.trim().equals(""))
                params.put(sys.getId(), type);
        }

        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Reads server statistics.
     */
    private void readStat(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        IConfigStore cs = CMS.getConfigStore();
        try {
            String installdate = cs.getString(Constants.PR_STAT_INSTALLDATE, "");
            params.put(Constants.PR_STAT_INSTALLDATE, installdate);
        } catch (Exception e) {
        }

        try {
            String version = cs.getString(Constants.PR_STAT_VERSION, "");
            params.put(Constants.PR_STAT_VERSION, version);
        } catch (Exception e) {
        }

        try {
            String instanceId = cs.getString(Constants.PR_STAT_INSTANCEID, "");
            params.put(Constants.PR_STAT_INSTANCEID, instanceId);
        } catch (Exception e) {
        }

        params.put(Constants.PR_STAT_STARTUP,
                (new Date(CMS.getStartupTime())).toString());
        params.put(Constants.PR_STAT_TIME,
                (new Date(System.currentTimeMillis())).toString());
        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Modifies database information.
     */
    private void setDBConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        IConfigStore dbConfig = mConfig.getSubStore(PROP_INTERNAL_DB);
        Enumeration<String> enum1 = req.getParameterNames();

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();

            if (key.equals(Constants.OP_TYPE))
                continue;
            if (key.equals(Constants.RS_ID))
                continue;
            if (key.equals(Constants.OP_SCOPE))
                continue;

            dbConfig.putString(key, req.getParameter(key));
        }

        sendResponse(RESTART, null, null, resp);
        mConfig.commit(true);
    }

    /**
     * Create Master Key
     */
    private void createMasterKey(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = req.getParameterNames();
        String newKeyName = null, selectedToken = null;
        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.PR_KEY_LIST)) {
                newKeyName = req.getParameter(name);
            }
            if (name.equals(Constants.PR_TOKEN_LIST)) {
                selectedToken = req.getParameter(name);
            }

        }
        if (selectedToken != null && newKeyName != null) {
            SessionKey.GenMasterKey(selectedToken, newKeyName); // check for errors
            CMS.getConfigStore().putString("tks.defaultSlot", selectedToken);
            String masterKeyPrefix = CMS.getConfigStore().getString("tks.master_key_prefix", null);

            SessionKey.SetDefaultPrefix(masterKeyPrefix);
            params.put(Constants.PR_KEY_LIST, newKeyName);
            params.put(Constants.PR_TOKEN_LIST, selectedToken);
        }
        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Reads secmod.db
     */
    private void getTKSKeys(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.PR_TOKEN_LIST)) {
                String selectedToken = req.getParameter(name);

                ICryptoSubsystem jssSubSystem = (ICryptoSubsystem) CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);

                CryptoToken token = null;
                CryptoManager mCryptoManager = null;
                try {
                    mCryptoManager = CryptoManager.getInstance();
                } catch (Exception e2) {
                }

                if (!jssSubSystem.isTokenLoggedIn(selectedToken)) {
                    PasswordCallback cpcb = new ConsolePasswordCallback();
                    while (true) {
                        try {
                            token = mCryptoManager.getTokenByName(selectedToken);
                            token.login(cpcb);
                            break;
                        } catch (Exception e3) {
                            //log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_SECURITY_INCORRECT_PWD"));
                            continue;
                        }
                    }
                }
                // String symKeys = new String("key1,key2");
                String symKeys = SessionKey.ListSymmetricKeys(selectedToken);
                params.put(Constants.PR_TOKEN_LIST, symKeys);

            }
        }
        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Reads database information.
     */
    private void getDBConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        IConfigStore dbConfig = mConfig.getSubStore(PROP_DB);
        IConfigStore ldapConfig = dbConfig.getSubStore("ldap");
        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = req.getParameterNames();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.OP_TYPE))
                continue;
            if (name.equals(Constants.RS_ID))
                continue;
            if (name.equals(Constants.OP_SCOPE))
                continue;
            if (name.equals(Constants.PR_SECURE_PORT_ENABLED))
                params.put(name, ldapConfig.getString(name, "Constants.FALSE"));
            else
                params.put(name, ldapConfig.getString(name, ""));
        }
        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Modifies SMTP configuration.
     */
    private void modifySMTPConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        // XXX
        IConfigStore sConfig = mConfig.getSubStore(PROP_SMTP);

        String host = req.getParameter(Constants.PR_SERVER_NAME);

        if (host != null)
            sConfig.putString("host", host);

        String port = req.getParameter(Constants.PR_PORT);

        if (port != null)
            sConfig.putString("port", port);

        commit(true);

        sendResponse(SUCCESS, null, null, resp);
    }

    /**
     * Reads SMTP configuration.
     */
    private void readSMTPConfig(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        IConfigStore dbConfig = mConfig.getSubStore(PROP_SMTP);
        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_SERVER_NAME,
                dbConfig.getString("host"));
        params.put(Constants.PR_PORT,
                dbConfig.getString("port"));
        sendResponse(SUCCESS, null, params, resp);
    }

    private void loggedInToken(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();
        String tokenName = "";
        String pwd = "";

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(Constants.PR_TOKEN_NAME)) {
                tokenName = value;
            } else if (key.equals(Constants.PR_TOKEN_PASSWD)) {
                pwd = value;
            }
        }

        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);

        jssSubSystem.loggedInToken(tokenName, pwd);

        /* Do a "PUT" of the new pw to the watchdog" */
        CMS.putPasswordCache(tokenName, pwd);
        sendResponse(SUCCESS, null, null, resp);
    }

    private void checkTokenStatus(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();
        String key = "";
        String value = "";

        while (enum1.hasMoreElements()) {
            key = enum1.nextElement();
            value = req.getParameter(key);
            if (key.equals(Constants.PR_TOKEN_NAME)) {
                break;
            }
        }

        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        boolean status = jssSubSystem.isTokenLoggedIn(value);

        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_LOGGED_IN, "" + status);

        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Retrieve a certificate request
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_KEY_GEN_ASYMMETRIC used when asymmetric keys are generated
     * </ul>
     *
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException failed to retrieve certificate request
     */
    private void getCertRequest(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditPublicKey = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();
            Enumeration<String> enum1 = req.getParameterNames();
            String tokenName = Constants.PR_INTERNAL_TOKEN_NAME;
            String keyType = "";
            int keyLength = 512;
            String subjectName = "";
            String certType = Constants.PR_CA_SIGNING_CERT;
            String dir = "";
            String pathname = "";
            String otherNickname = "";
            String keyCurveName = "";

            while (enum1.hasMoreElements()) {
                String key = enum1.nextElement();
                String value = req.getParameter(key);

                if (key.equals(Constants.PR_TOKEN_NAME)) {
                    if (!value.equals(Constants.PR_INTERNAL_TOKEN))
                        tokenName = value;
                } else if (key.equals(Constants.PR_KEY_LENGTH)) {
                    keyLength = Integer.parseInt(value);
                } else if (key.equals(Constants.PR_KEY_TYPE)) {
                    keyType = value;
                } else if (key.equals(Constants.RS_ID)) {
                    certType = value;
                } else if (key.equals(Constants.PR_SUBJECT_NAME)) {
                    subjectName = value;
                } else if (key.equals(Constants.PR_NICKNAME)) {
                    otherNickname = value;
                } else if (key.equals(Constants.PR_KEY_CURVENAME)) {
                    keyCurveName = value;
                }
            }

            pathname = mConfig.getString("instanceRoot", "")
                    + File.separator + "conf" + File.separator;
            dir = pathname;
            ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                    CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);

            KeyPair keypair = null;
            PQGParams pqgParams = null;
            String nickname = "";

            // other cert and has the existing key
            if (certType.equals(Constants.PR_OTHER_CERT) && keyType.equals(""))
                nickname = otherNickname;
            else if (!certType.equals(Constants.PR_OTHER_CERT))
                nickname = getNickname(certType);

            String nicknameWithoutTokenName = "";

            if (nickname != null && !nickname.equals("")) {
                int index = nickname.indexOf(":");

                nicknameWithoutTokenName = nickname;
                if (index >= 0)
                    nicknameWithoutTokenName = nickname.substring(index + 1);
            }

            if (keyType.equals("")) {
                if (nickname.equals("")) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_KEY_GEN_ASYMMETRIC,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditPublicKey);

                    audit(auditMessage);

                    throw new EBaseException(
                            CMS.getLogMessage("BASE_CERT_NOT_FOUND"));
                }
                keypair = jssSubSystem.getKeyPair(nickname);
            } else {
                if (keyType.equals("ECC")) {
                    // get ECC keypair
                    keypair = jssSubSystem.getECCKeyPair(tokenName, keyCurveName, certType);
                } else { //DSA or RSA
                    if (keyType.equals("DSA"))
                        pqgParams = jssSubSystem.getPQG(keyLength);
                    keypair = jssSubSystem.getKeyPair(tokenName, keyType, keyLength, pqgParams);
                }
            }

            // reset the "auditPublicKey"
            auditPublicKey = auditPublicKey(keypair);

            if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                pathname = pathname + File.separator + "cacsr.txt";
                if (!keyType.equals(""))
                    setCANewnickname(tokenName, nicknameWithoutTokenName);
            } else if (certType.equals(Constants.PR_RA_SIGNING_CERT)) {
                pathname = pathname + File.separator + "racsr.txt";
                if (!keyType.equals(""))
                    setRANewnickname(tokenName, nicknameWithoutTokenName);
            } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
                pathname = pathname + File.separator + "ocspcsr.txt";
                if (!keyType.equals(""))
                    setOCSPNewnickname(tokenName, nicknameWithoutTokenName);
            } else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT)) {
                pathname = pathname + File.separator + "kracsr.txt";
                if (!keyType.equals(""))
                    setKRANewnickname(tokenName, nicknameWithoutTokenName);
            } else if (certType.equals(Constants.PR_SERVER_CERT)) {
                pathname = pathname + File.separator + "sslcsr.txt";
                if (!keyType.equals(""))
                    setAgentNewnickname(tokenName, nicknameWithoutTokenName);
            } else if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
                pathname = pathname + File.separator + "sslcsrradm.txt";
                if (!keyType.equals(""))
                    setRADMNewnickname(tokenName, nicknameWithoutTokenName);
            } else if (certType.equals(Constants.PR_OTHER_CERT)) {
                pathname = pathname + File.separator + "othercsr.txt";
            }
            String certReq = jssSubSystem.getCertRequest(subjectName, keypair);

            params.put(Constants.PR_CSR, certReq);
            params.put(Constants.PR_CERT_REQUEST_DIR, dir);
            PrintStream ps = new PrintStream(new FileOutputStream(pathname));

            ps.println(certReq);
            ps.close();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_KEY_GEN_ASYMMETRIC,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditPublicKey);

            audit(auditMessage);

            mConfig.commit(true);
            sendResponse(SUCCESS, null, params, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_KEY_GEN_ASYMMETRIC,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditPublicKey);

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_KEY_GEN_ASYMMETRIC,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditPublicKey);

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_KEY_GEN_ASYMMETRIC,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditPublicKey );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    private void setCANewnickname(String tokenName, String nickname)
            throws EBaseException {
        ICertificateAuthority ca = (ICertificateAuthority)
                CMS.getSubsystem(CMS.SUBSYSTEM_CA);
        ISigningUnit signingUnit = ca.getSigningUnit();

        if (tokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME))
            signingUnit.setNewNickName(nickname);
        else {
            if (tokenName.equals("") && nickname.equals(""))
                signingUnit.setNewNickName("");
            else
                signingUnit.setNewNickName(tokenName + ":" + nickname);
        }
    }

    private String getCANewnickname() throws EBaseException {
        ICertificateAuthority ca = (ICertificateAuthority)
                CMS.getSubsystem(CMS.SUBSYSTEM_CA);
        ISigningUnit signingUnit = ca.getSigningUnit();

        return signingUnit.getNewNickName();
    }

    private void setRANewnickname(String tokenName, String nickname)
            throws EBaseException {
        IRegistrationAuthority ra = (IRegistrationAuthority)
                CMS.getSubsystem(CMS.SUBSYSTEM_RA);

        if (tokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME))
            ra.setNewNickName(nickname);
        else {
            if (tokenName.equals("") && nickname.equals(""))
                ra.setNewNickName("");
            else
                ra.setNewNickName(tokenName + ":" + nickname);
        }
    }

    private String getRANewnickname() throws EBaseException {
        IRegistrationAuthority ra = (IRegistrationAuthority)
                CMS.getSubsystem(CMS.SUBSYSTEM_RA);

        return ra.getNewNickName();
    }

    private void setOCSPNewnickname(String tokenName, String nickname)
            throws EBaseException {
        IOCSPAuthority ocsp = (IOCSPAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_OCSP);

        if (ocsp != null) {
            ISigningUnit signingUnit = ocsp.getSigningUnit();

            if (tokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME))
                signingUnit.setNewNickName(nickname);
            else {
                if (tokenName.equals("") && nickname.equals(""))
                    signingUnit.setNewNickName("");
                else
                    signingUnit.setNewNickName(tokenName + ":" + nickname);
            }
        } else {
            ICertificateAuthority ca = (ICertificateAuthority)
                    CMS.getSubsystem(CMS.SUBSYSTEM_CA);
            ISigningUnit signingUnit = ca.getOCSPSigningUnit();

            if (tokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME))
                signingUnit.setNewNickName(nickname);
            else {
                if (tokenName.equals("") && nickname.equals(""))
                    signingUnit.setNewNickName("");
                else
                    signingUnit.setNewNickName(tokenName + ":" + nickname);
            }
        }
    }

    private String getOCSPNewnickname() throws EBaseException {
        IOCSPAuthority ocsp = (IOCSPAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_OCSP);

        if (ocsp != null) {
            ISigningUnit signingUnit = ocsp.getSigningUnit();

            return signingUnit.getNewNickName();
        } else {
            ICertificateAuthority ca = (ICertificateAuthority)
                    CMS.getSubsystem(CMS.SUBSYSTEM_CA);
            ISigningUnit signingUnit = ca.getOCSPSigningUnit();

            return signingUnit.getNewNickName();
        }
    }

    private void setKRANewnickname(String tokenName, String nickname)
            throws EBaseException {
        IKeyRecoveryAuthority kra = (IKeyRecoveryAuthority)
                CMS.getSubsystem(CMS.SUBSYSTEM_KRA);

        if (tokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME))
            kra.setNewNickName(nickname);
        else {
            if (tokenName.equals("") && nickname.equals(""))
                kra.setNewNickName("");
            else
                kra.setNewNickName(tokenName + ":" + nickname);
        }
    }

    private String getKRANewnickname() throws EBaseException {
        IKeyRecoveryAuthority kra = (IKeyRecoveryAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_KRA);

        return kra.getNewNickName();
    }

    private void setRADMNewnickname(String tokenName, String nickName)
            throws EBaseException {
        CMS.setServerCertNickname(tokenName, nickName);

        /*
         RemoteAdmin raAdmin = (RemoteAdmin)RemoteAdmin.getInstance();
         HTTPService httpsService = raAdmin.getHttpsService();
         if (tokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME))
         httpsService.setNewNickName(nickName);
         else {
         if (tokenName.equals("") && nickName.equals(""))
         httpsService.setNewNickName("");
         else
         httpsService.setNewNickName(tokenName+":"+nickName);
         }
         */
    }

    private String getRADMNewnickname()
            throws EBaseException {
        // assuming the nickname does not change.
        return CMS.getServerCertNickname();

        /*
         RemoteAdmin raAdmin = (RemoteAdmin)RemoteAdmin.getInstance();
         HTTPService httpsService = raAdmin.getHttpsService();
         return httpsService.getNewNickName();
         */
    }

    private void setAgentNewnickname(String tokenName, String nickName)
            throws EBaseException {
        CMS.setServerCertNickname(tokenName, nickName);

        /*
         AgentGateway gateway = (AgentGateway)mReg.get(AgentGateway.ID);
         HTTPService httpsService = gateway.getHttpsService();
         if (tokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME))
         httpsService.setNewNickName(nickName);
         else {
         if (tokenName.equals("") && nickName.equals(""))
         httpsService.setNewNickName("");
         else
         httpsService.setNewNickName(tokenName+":"+nickName);
         }
         */
    }

    private String getAgentNewnickname()
            throws EBaseException {
        // assuming the nickname does not change.
        return CMS.getServerCertNickname();

        /*
         AgentGateway gateway = (AgentGateway)mReg.get(AgentGateway.ID);
         HTTPService httpsService = gateway.getHttpsService();
         return httpsService.getNewNickName();
         */
    }

    /**
     * Issue import certificate
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY used when "Certificate Setup Wizard" is used to
     * import CA certs into the certificate database
     * </ul>
     *
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException failed to issue an import certificate
     */
    private void issueImportCert(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            Enumeration<String> enum1 = req.getParameterNames();
            String tokenName = Constants.PR_INTERNAL_TOKEN_NAME;
            String keyType = "RSA";
            KeyCertData properties = new KeyCertData();

            String newtokenname = null;

            while (enum1.hasMoreElements()) {
                String key = enum1.nextElement();
                String value = req.getParameter(key);

                if (!key.equals("pathname")) {
                    if (key.equals(Constants.PR_TOKEN_NAME))
                        newtokenname = value;
                    properties.put(key, value);
                }
            }

            String certType = (String) properties.get(Constants.RS_ID);

            ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                    CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
            ICertificateAuthority ca = (ICertificateAuthority)
                    CMS.getSubsystem(CMS.SUBSYSTEM_CA);
            ICertificateRepository repository =
                    ca.getCertificateRepository();
            ISigningUnit signingUnit = ca.getSigningUnit();
            String oldtokenname = null;
            //this is the old nick name
            String nickname = getNickname(certType);
            String nicknameWithoutTokenName = "";
            String oldcatokenname = signingUnit.getTokenName();
            String canickname = getNickname(Constants.PR_CA_SIGNING_CERT);
            String canicknameWithoutTokenName = "";

            int index = nickname.indexOf(":");

            if (index == -1) {
                nicknameWithoutTokenName = nickname;
                oldtokenname = Constants.PR_INTERNAL_TOKEN_NAME;
            } else if (index > 0 && (index < (nickname.length() - 1))) {
                nicknameWithoutTokenName = nickname.substring(index + 1);
                oldtokenname = nickname.substring(0, index);
            } else {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                throw new EBaseException(CMS.getLogMessage("BASE_CERT_NOT_FOUND"));
            }

            if (newtokenname == null)
                newtokenname = oldtokenname;
            index = canickname.indexOf(":");
            if (index == -1) {
                canicknameWithoutTokenName = canickname;
            } else if (index > 0 && (index < (canickname.length() - 1))) {
                canicknameWithoutTokenName = canickname.substring(index + 1);
            } else {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                throw new EBaseException(CMS.getLogMessage("BASE_CERT_NOT_FOUND"));
            }

            //xxx renew ca ,use old issuer?
            properties.setIssuerName(
                    jssSubSystem.getCertSubjectName(oldcatokenname,
                                                canicknameWithoutTokenName));

            KeyPair pair = null;

            if (nickname.equals("")) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                throw new EBaseException(CMS.getLogMessage("BASE_CERT_NOT_FOUND"));
            }

            //xxx set to old nickname?
            properties.setCertNickname(nickname);
            if (!certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                CertificateExtensions exts = jssSubSystem.getExtensions(
                        oldcatokenname, canicknameWithoutTokenName);

                properties.setCAExtensions(exts);
            }

            KeyPair caKeyPair = null;
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

            // create a new CA certificate or ssl server cert
            if (properties.getKeyCurveName() != null) { //new ECC
                CMS.debug("CMSAdminServlet: issueImportCert: generating ECC keys");
                pair = jssSubSystem.getECCKeyPair(properties);
                if (certType.equals(Constants.PR_CA_SIGNING_CERT))
                    caKeyPair = pair;
            } else if (properties.getKeyLength() != null) { //new RSA or DSA
                keyType = properties.getKeyType();
                String keyLen = properties.getKeyLength();

                if (keyType.equals("DSA")) {
                    @SuppressWarnings("unused")
                    PQGParams pqgParams =
                            jssSubSystem.getCAPQG(Integer.parseInt(keyLen), mConfig); // check for errors
                    //properties.put(Constants.PR_PQGPARAMS, pqgParams);
                }
                pair = jssSubSystem.getKeyPair(properties);
                if (certType.equals(Constants.PR_CA_SIGNING_CERT))
                    caKeyPair = pair;
                // renew the CA certificate or ssl server cert
            } else {
                pair = jssSubSystem.getKeyPair(nickname);
                // should get it from the CA signing certificate
                if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                    updateCASignature(nickname, properties, jssSubSystem);
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
                caKeyPair = jssSubSystem.getKeyPair(canickname);
                updateCASignature(canickname, properties, jssSubSystem);
            } else if (alg != null) {
                // self signed CA signing cert, new keys
                // value provided for signedBy
                SignatureAlgorithm sigAlg = Cert.mapAlgorithmToJss(alg);
                properties.setSignatureAlgorithm(sigAlg);
                properties.setAlgorithmId(jssSubSystem.getAlgorithmId(alg, mConfig));
            }

            if (pair == null)
                CMS.debug("CMSAdminServlet: issueImportCert: key pair is null");

            BigInteger nextSerialNo = repository.getNextSerialNumber();

            properties.setSerialNumber(nextSerialNo);
            properties.setKeyPair(pair);
            properties.setConfigFile(mConfig);
            //        properties.put(Constants.PR_CA_KEYPAIR, pair);
            properties.put(Constants.PR_CA_KEYPAIR, caKeyPair);

            X509CertImpl signedCert =
                    jssSubSystem.getSignedCert(properties, certType,
                                           caKeyPair.getPrivate());

            if (signedCert == null)
                CMS.debug("CMSAdminServlet: issueImportCert: signedCert is null");

            /* bug 600124
             try {
                 jssSubSystem.deleteTokenCertificate(nickname, pathname);
             } catch (Throwable e) {
                 //skip it
             }
             */

            boolean nicknameChanged = false;

            //xxx import cert with nickname without token name?
            //jss adds the token prefix!!!
            //log(ILogger.LL_DEBUG,"import as alias"+ nicknameWithoutTokenName);
            try {
                CMS.debug("CMSAdminServlet: issueImportCert: Importing cert: " + nicknameWithoutTokenName);
                jssSubSystem.importCert(signedCert, nicknameWithoutTokenName,
                                        certType);
            } catch (EBaseException e) {
                // if it fails, let use a different nickname to try
                Date now = new Date();
                String newNickname = nicknameWithoutTokenName
                                   + "-" + now.getTime();

                CMS.debug("CMSAdminServlet: issueImportCert: Importing cert with nickname: " + newNickname);
                jssSubSystem.importCert(signedCert, newNickname,
                                        certType);
                nicknameWithoutTokenName = newNickname;
                nicknameChanged = true;
                if (tokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
                    nickname = newNickname;
                } else {
                    nickname = tokenName + ":" + newNickname;
                }
            }

            ICertRecord certRecord = repository.createCertRecord(
                                         signedCert.getSerialNumber(),
                                         signedCert, null);

            repository.addCertificateRecord(certRecord);

            if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                try {
                    X509CertInfo certInfo = (X509CertInfo) signedCert.get(
                            X509CertImpl.NAME + "." + X509CertImpl.INFO);
                    CertificateExtensions extensions = (CertificateExtensions)
                            certInfo.get(X509CertInfo.EXTENSIONS);

                    if (extensions != null) {
                        BasicConstraintsExtension basic =
                                (BasicConstraintsExtension)
                                extensions.get(BasicConstraintsExtension.NAME);

                        if (basic == null)
                            log(CMS.getLogMessage("ADMIN_SRVLT_BASIC_CONSTRAIN_NULL"));
                        else {
                            Integer pathlen = (Integer)
                                    basic.get(BasicConstraintsExtension.PATH_LEN);
                            int num = pathlen.intValue();

                            if (num == 0)
                                ca.setBasicConstraintMaxLen(num);
                            else if (num > 0) {
                                num = num - 1;
                                ca.setBasicConstraintMaxLen(num);
                            }
                        }
                    } else
                        log(CMS.getLogMessage("ADMIN_SRVLT_CERT_NO_EXT"));
                } catch (Exception eee) {
                    log("CMSAdminServlet: Exception caught: " + eee.toString());
                }
            }

            CMS.debug("CMSAdminServlet: oldtoken:" + oldtokenname
                    + " newtoken:" + newtokenname + " nickname:" + nickname);
            if ((newtokenname != null &&
                    !newtokenname.equals(oldtokenname)) || nicknameChanged) {
                if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                    if (newtokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
                        signingUnit.updateConfig(nicknameWithoutTokenName,
                                                 newtokenname);
                    } else {
                        signingUnit.updateConfig(newtokenname + ":" +
                                                 nicknameWithoutTokenName,
                                                 newtokenname);
                    }
                } else if (certType.equals(Constants.PR_SERVER_CERT)) {
                    if (newtokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
                        nickname = nicknameWithoutTokenName;
                    } else {
                        nickname = newtokenname + ":"
                                 + nicknameWithoutTokenName;
                    }

                    //setRADMNewnickname("","");
                    //modifyRADMCert(nickname);
                    modifyAgentGatewayCert(nickname);
                    if (isSubsystemInstalled("ra")) {
                        IRegistrationAuthority ra =
                                (IRegistrationAuthority)
                                CMS.getSubsystem(CMS.SUBSYSTEM_RA);

                        modifyEEGatewayCert(ra, nickname);
                    }
                    if (isSubsystemInstalled("ca")) {
                        modifyCAGatewayCert(ca, nickname);
                    }
                } else if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
                    if (newtokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
                        nickname = nicknameWithoutTokenName;
                    } else {
                        nickname = newtokenname + ":"
                                 + nicknameWithoutTokenName;
                    }

                    modifyRADMCert(nickname);
                } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
                    if (ca != null) {
                        ISigningUnit ocspSigningUnit = ca.getOCSPSigningUnit();

                        if (newtokenname.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
                            ocspSigningUnit.updateConfig(
                                    nicknameWithoutTokenName, newtokenname);
                        } else {
                            ocspSigningUnit.updateConfig(newtokenname + ":" +
                                    nicknameWithoutTokenName,
                                    newtokenname);
                        }
                    }
                }
            }

            // set signing algorithms if needed
            if (certType.equals(Constants.PR_CA_SIGNING_CERT))
                signingUnit.setDefaultAlgorithm(defaultSigningAlg);

            if (defaultOCSPSigningAlg != null) {
                ISigningUnit ocspSigningUnit = ca.getOCSPSigningUnit();
                ocspSigningUnit.setDefaultAlgorithm(defaultOCSPSigningAlg);
            }

            properties.clear();
            properties = null;

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            mConfig.commit(true);
            sendResponse(SUCCESS, null, null, resp);
        } catch (EBaseException eAudit1) {
            CMS.debug("CMSAdminServlet: issueImportCert: EBaseException thrown: " + eAudit1.toString());
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            CMS.debug("CMSAdminServlet: issueImportCert: IOException thrown: " + eAudit2.toString());
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    private void updateCASignature(String nickname, KeyCertData properties,
            ICryptoSubsystem jssSubSystem) throws EBaseException {
        String alg = jssSubSystem.getSignatureAlgorithm(nickname);
        SignatureAlgorithm sigAlg = Cert.mapAlgorithmToJss(alg);

        properties.setSignatureAlgorithm(sigAlg);
        properties.setAlgorithmId(
                jssSubSystem.getAlgorithmId(alg, mConfig));
    }

    /**
     * Install certificates
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY used when "Certificate Setup Wizard" is used to
     * import CA certs into the certificate database
     * </ul>
     *
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException failed to install a certificate
     */
    private void installCert(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String tokenName = Constants.PR_INTERNAL_TOKEN_NAME;
            String pkcs = "";
            String certType = "";
            String nickname = "";
            String pathname = "";
            String serverRoot = "";
            String serverID = "";
            String certpath = "";
            Enumeration<String> enum1 = req.getParameterNames();

            while (enum1.hasMoreElements()) {
                String key = enum1.nextElement();
                String value = req.getParameter(key);

                if (key.equals(Constants.PR_PKCS10))
                    pkcs = value;
                else if (key.equals(Constants.RS_ID))
                    certType = value;
                else if (key.equals(Constants.PR_NICKNAME))
                    nickname = value;
                else if (key.equals("pathname"))
                    pathname = value;
                else if (key.equals(Constants.PR_SERVER_ROOT))
                    serverRoot = value;
                else if (key.equals(Constants.PR_SERVER_ID))
                    serverID = value;
                else if (key.equals(Constants.PR_CERT_FILEPATH))
                    certpath = value;
            }

            try {
                if (pkcs == null || pkcs.equals("")) {
                    if (certpath == null || certpath.equals("")) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                        audit(auditMessage);

                        EBaseException ex = new EBaseException(
                                CMS.getLogMessage("BASE_INVALID_FILE_PATH"));

                        throw ex;
                    } else {
                        FileInputStream in = new FileInputStream(certpath);
                        BufferedReader d =
                                new BufferedReader(new InputStreamReader(in));
                        String content = "";

                        pkcs = "";
                        StringBuffer sb = new StringBuffer();
                        while ((content = d.readLine()) != null) {
                            sb.append(content);
                            sb.append("\n");
                        }

                        pkcs = sb.toString();
                        if (d != null) {
                            d.close();
                        }
                        pkcs = pkcs.substring(0, pkcs.length() - 1);
                    }
                }
            } catch (IOException ee) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                throw new EBaseException(
                        CMS.getLogMessage("BASE_OPEN_FILE_FAILED"));
            }

            pkcs = pkcs.trim();
            pathname = serverRoot + File.separator + serverID
                     + File.separator + "config" + File.separator + pathname;

            ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                    CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
            //String nickname = getNickname(certType);
            String nicknameWithoutTokenName = "";

            int index = nickname.indexOf(":");

            if (index == -1)
                nicknameWithoutTokenName = nickname;
            else if (index > 0 && (index < (nickname.length() - 1))) {
                tokenName = nickname.substring(0, index);
                nicknameWithoutTokenName = nickname.substring(index + 1);
            } else {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                throw new EBaseException(
                        CMS.getLogMessage("BASE_CERT_NOT_FOUND"));
            }

            /*
            if (certType.equals(Constants.PR_CA_SIGNING_CERT) ||
                certType.equals(Constants.PR_RA_SIGNING_CERT) ||
                certType.equals(Constants.PR_OCSP_SIGNING_CERT) ||
                certType.equals(Constants.PR_KRA_TRANSPORT_CERT) ||
                certType.equals(Constants.PR_SERVER_CERT) ||
                certType.equals(Constants.PR_SERVER_CERT_RADM)) {
                    String oldnickname = getNickname(certType);
                    try {
                        jssSubsystem.deleteTokenCertificate(oldnickname,
                                                            pathname);
                        //jssSubsystem.deleteTokenCertificate(nickname,
                                                              pathname);
                    } catch (EBaseException e) {
                        // skip it
                    }
            } else {
                try {
                    jssSubsystem.deleteTokenCertificate(nickname, pathname);
                } catch (EBaseException e) {
                    // skip it
                }
            }
            */

            // 600124 - renewal of SSL crash the server
            // we now do not delete previously installed certificates.

            // Same Subject   | Same Nickname |  Same Key  |     Legal
            // -----------------------------------------------------------
            // 1.   Yes             Yes            No              Yes
            // 2.   Yes             Yes            Yes             Yes
            // 3.   No              No             Yes             Yes
            // 4.   No              No             No              Yes
            // 5.   No              Yes            Yes             No
            // 6.   No              Yes            No              No
            // 7.   Yes             No             Yes             No
            // 8.   Yes             No             No              No

            // Based on above table, the following cases are permitted:
            // Existing Key:
            // 	(a) Same Subject & Same Nickname	        --- (2)
            // 	(b) Different Subject & Different Nickname	--- (3)
            //          (In order to support Case b., we need to use a different
            //		nickname).
            // New Key:
            //      (c) Same Subject & Same Nickname                --- (1)
            // 	(d) Different Subject & Different Nickname	--- (4)
            //          (In order to support Case b., we need to use a different
            //		nickname).
            //

            CMS.debug("CMSAdminServlet.installCert(): About to try jssSubSystem.importCert: "
                    + nicknameWithoutTokenName);
            try {
                jssSubSystem.importCert(pkcs, nicknameWithoutTokenName,
                        certType);
            } catch (EBaseException e) {

                boolean certFound = false;

                String eString = e.toString();
                if (eString.contains("Failed to find certificate that was just imported")) {
                    CMS.debug("CMSAdminServlet.installCert(): nickname="
                            + nicknameWithoutTokenName + " TokenException: " + eString);

                    X509Certificate cert = null;
                    try {
                        cert = CryptoManager.getInstance().findCertByNickname(nickname);
                        if (cert != null) {
                            certFound = true;
                        }
                        CMS.debug("CMSAdminServlet.installCert() Found cert just imported: " + nickname);
                    } catch (Exception ex) {
                        CMS.debug("CMSAdminServlet.installCert() Can't find cert just imported: " + ex.toString());
                    }
                }

                if (!certFound) {
                    // if it fails, let use a different nickname to try
                    Date now = new Date();
                    String newNickname = nicknameWithoutTokenName + "-" +
                                     now.getTime();

                    jssSubSystem.importCert(pkcs, newNickname, certType);
                    nicknameWithoutTokenName = newNickname;
                    if (tokenName.equals(Constants.PR_INTERNAL_TOKEN_NAME)) {
                        nickname = newNickname;
                    } else {
                        nickname = tokenName + ":" + newNickname;
                    }
                    CMS.debug("CMSAdminServlet: installCert():  After second install attempt following initial error: nickname="
                            + nickname);
                }
            }

            if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                ICertificateAuthority ca =
                        (ICertificateAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_CA);
                ISigningUnit signingUnit = ca.getSigningUnit();
                String signatureAlg =
                        jssSubSystem.getSignatureAlgorithm(nickname);

                signingUnit.setDefaultAlgorithm(signatureAlg);
                setCANewnickname("", "");
                try {
                    CertificateExtensions extensions = null;

                    if (nickname.equals(nicknameWithoutTokenName)) {
                        signingUnit.updateConfig(nickname,
                                Constants.PR_INTERNAL_TOKEN_NAME);
                        extensions = jssSubSystem.getExtensions(
                                Constants.PR_INTERNAL_TOKEN_NAME, nickname);
                    } else {
                        String tokenname1 = nickname.substring(0, index);

                        signingUnit.updateConfig(nickname, tokenname1);
                        extensions = jssSubSystem.getExtensions(tokenname1,
                                nicknameWithoutTokenName);
                    }
                    if (extensions != null) {
                        BasicConstraintsExtension basic =
                                (BasicConstraintsExtension)
                                extensions.get(BasicConstraintsExtension.NAME);

                        if (basic == null)
                            log(CMS.getLogMessage("ADMIN_SRVLT_BASIC_CONSTRAIN_NULL"));
                        else {
                            Integer pathlen = (Integer)
                                    basic.get(BasicConstraintsExtension.PATH_LEN);
                            int num = pathlen.intValue();

                            if (num == 0)
                                ca.setBasicConstraintMaxLen(num);
                            else if (num > 0) {
                                num = num - 1;
                                ca.setBasicConstraintMaxLen(num);
                            }
                        }
                    } else {
                        log(CMS.getLogMessage("ADMIN_SRVLT_CERT_NO_EXT"));
                    }
                } catch (Exception eee) {
                    log("CMSAdminServlet: Exception: " + eee.toString());
                }
            } else if (certType.equals(Constants.PR_RA_SIGNING_CERT)) {
                setRANewnickname("", "");
                IRegistrationAuthority ra =
                        (IRegistrationAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_RA);

                ra.setNickname(nickname);
            } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
                setOCSPNewnickname("", "");
                IOCSPAuthority ocsp =
                        (IOCSPAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_OCSP);

                if (ocsp != null) {
                    ISigningUnit signingUnit = ocsp.getSigningUnit();

                    if (nickname.equals(nicknameWithoutTokenName)) {
                        signingUnit.updateConfig(nickname,
                                Constants.PR_INTERNAL_TOKEN_NAME);
                    } else {
                        String tokenname1 = nickname.substring(0, index);

                        signingUnit.updateConfig(nickname, tokenname1);
                    }
                } else {
                    ICertificateAuthority ca =
                            (ICertificateAuthority)
                            CMS.getSubsystem(CMS.SUBSYSTEM_CA);
                    ISigningUnit signingUnit = ca.getOCSPSigningUnit();

                    if (nickname.equals(nicknameWithoutTokenName)) {
                        signingUnit.updateConfig(nickname,
                                Constants.PR_INTERNAL_TOKEN_NAME);
                    } else {
                        String tokenname1 = nickname.substring(0, index);

                        signingUnit.updateConfig(nickname, tokenname1);
                    }
                }
            } else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT)) {
                setKRANewnickname("", "");
                IKeyRecoveryAuthority kra =
                        (IKeyRecoveryAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_KRA);

                kra.setNickname(nickname);
            } else if (certType.equals(Constants.PR_SERVER_CERT)) {
                setAgentNewnickname("", "");
                //modifyRADMCert(nickname);
                modifyAgentGatewayCert(nickname);
                if (isSubsystemInstalled("ra")) {
                    IRegistrationAuthority ra =
                            (IRegistrationAuthority)
                            CMS.getSubsystem(CMS.SUBSYSTEM_RA);

                    modifyEEGatewayCert(ra, nickname);
                }
                if (isSubsystemInstalled("ca")) {
                    ICertificateAuthority ca =
                            (ICertificateAuthority)
                            CMS.getSubsystem(CMS.SUBSYSTEM_CA);

                    modifyCAGatewayCert(ca, nickname);
                }
            } else if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
                setRADMNewnickname("", "");
                modifyRADMCert(nickname);
            }

            boolean verified = CMS.verifySystemCertByNickname(nickname, null);
            if (verified == true) {
                CMS.debug("CMSAdminServlet: installCert(): verifySystemCertByNickname() succeeded:" + nickname);
                auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CIMC_CERT_VERIFICATION,
                        auditSubjectID,
                        ILogger.SUCCESS,
                                nickname);

                audit(auditMessage);
            } else {
                CMS.debug("CMSAdminServlet: installCert(): verifySystemCertByNickname() failed:" + nickname);
                auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CIMC_CERT_VERIFICATION,
                                auditSubjectID,
                                ILogger.FAILURE,
                                nickname);

                audit(auditMessage);
            }
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            mConfig.commit(true);
            if (verified == true) {
                sendResponse(SUCCESS, null, null, resp);
            } else {
                sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_CERT_VALIDATE_FAILED"),
                        null, resp);
            }
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    /**
     * For "importing" cross-signed cert into internal db for further
     * cross pair matching and publishing
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY used when "Certificate Setup Wizard" is used to
     * import a CA cross-signed certificate into the database
     * </ul>
     *
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException failed to import a cross-certificate pair
     */
    private void importXCert(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String b64Cert = "";
            String pathname = "";
            String serverRoot = "";
            String serverID = "";
            String certpath = "";
            Enumeration<String> enum1 = req.getParameterNames();
            NameValuePairs results = new NameValuePairs();

            while (enum1.hasMoreElements()) {
                String key = enum1.nextElement();
                String value = req.getParameter(key);

                // really should be PR_CERT_CONTENT
                if (key.equals(Constants.PR_PKCS10))
                    b64Cert = value;
                else if (key.equals("pathname"))
                    pathname = value;
                else if (key.equals(Constants.PR_SERVER_ROOT))
                    serverRoot = value;
                else if (key.equals(Constants.PR_SERVER_ID))
                    serverID = value;
                else if (key.equals(Constants.PR_CERT_FILEPATH))
                    certpath = value;
            }

            try {
                if (b64Cert == null || b64Cert.equals("")) {
                    if (certpath == null || certpath.equals("")) {
                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req));

                        audit(auditMessage);

                        EBaseException ex = new EBaseException(
                                CMS.getLogMessage("BASE_INVALID_FILE_PATH"));

                        throw ex;
                    } else {
                        FileInputStream in = new FileInputStream(certpath);
                        BufferedReader d =
                                new BufferedReader(new InputStreamReader(in));
                        String content = "";

                        b64Cert = "";
                        StringBuffer sb = new StringBuffer();
                        while ((content = d.readLine()) != null) {
                            sb.append(content);
                            sb.append("\n");
                        }
                        b64Cert = sb.toString();
                        if (d != null) {
                            d.close();
                        }
                        b64Cert = b64Cert.substring(0, b64Cert.length() - 1);
                    }
                }
            } catch (IOException ee) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                throw new EBaseException(
                        CMS.getLogMessage("BASE_OPEN_FILE_FAILED"));
            }
            CMS.debug("CMSAdminServlet: got b64Cert");
            b64Cert = Cert.stripBrackets(b64Cert.trim());

            // Base64 decode cert
            byte[] bCert = null;

            try {
                bCert = Utils.base64decode(b64Cert);
            } catch (Exception e) {
                CMS.debug("CMSAdminServlet: exception: " + e.toString());
            }

            pathname = serverRoot + File.separator + serverID
                     + File.separator + "config" + File.separator + pathname;

            ICrossCertPairSubsystem ccps =
                    (ICrossCertPairSubsystem) CMS.getSubsystem("CrossCertPair");

            try {
                //this will import into internal ldap crossCerts entry
                ccps.importCert(bCert);
            } catch (Exception e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(1, "xcert importing failure:" + e.toString(),
                             null, resp);
                return;
            }

            try {
                // this will publish all of the cross cert pairs from internal
                // db to publishing directory, if turned on
                ccps.publishCertPairs();
            } catch (EBaseException e) {
                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req));

                audit(auditMessage);

                sendResponse(1, "xcerts publishing failure:" + e.toString(), null, resp);
                return;
            }

            ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                    CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
            String content = jssSubSystem.getCertPrettyPrint(b64Cert,
                    super.getLocale(req));

            results.put(Constants.PR_NICKNAME, "FBCA cross-signed cert");
            results.put(Constants.PR_CERT_CONTENT, content);

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            sendResponse(SUCCESS, null, results, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    private String getNickname(String certType) throws EBaseException {
        String nickname = "";

        if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
            ICertificateAuthority ca =
                    (ICertificateAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_CA);
            ISigningUnit signingUnit = ca.getSigningUnit();

            nickname = signingUnit.getNickname();
        } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
            IOCSPAuthority ocsp =
                    (IOCSPAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_OCSP);

            if (ocsp == null) {
                // this is a local CA service
                ICertificateAuthority ca = (ICertificateAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_CA);
                ISigningUnit signingUnit = ca.getOCSPSigningUnit();

                nickname = signingUnit.getNickname();
            } else {
                ISigningUnit signingUnit = ocsp.getSigningUnit();

                nickname = signingUnit.getNickname();
            }
        } else if (certType.equals(Constants.PR_RA_SIGNING_CERT)) {
            IRegistrationAuthority ra =
                    (IRegistrationAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_RA);

            nickname = ra.getNickname();
        } else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT)) {
            IKeyRecoveryAuthority kra =
                    (IKeyRecoveryAuthority) CMS.getSubsystem(CMS.SUBSYSTEM_KRA);

            nickname = kra.getNickname();
        } else if (certType.equals(Constants.PR_SERVER_CERT)) {
            nickname = CMS.getServerCertNickname();
        } else if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
            nickname = CMS.getServerCertNickname();
        }

        return nickname;
    }

    private void getCertInfo(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();
        NameValuePairs results = new NameValuePairs();
        String pkcs = "";
        String path = "";
        String certType = "";
        String otherNickname = "";

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(Constants.PR_PKCS10)) {
                pkcs = value;
            } else if (key.equals(Constants.RS_ID)) {
                certType = value;
            } else if (key.equals(Constants.PR_CERT_FILEPATH)) {
                path = value;
            } else if (key.equals(Constants.PR_NICKNAME)) {
                otherNickname = value;
            }
        }

        try {
            if (pkcs == null || pkcs.equals("")) {

                if (path == null || path.equals("")) {
                    EBaseException ex = new EBaseException(
                            CMS.getLogMessage("BASE_INVALID_FILE_PATH"));

                    throw ex;
                } else {
                    FileInputStream in = new FileInputStream(path);
                    BufferedReader d =
                            new BufferedReader(new InputStreamReader(in));
                    String content = "";

                    pkcs = "";
                    StringBuffer sb = new StringBuffer();
                    while ((content = d.readLine()) != null) {
                        sb.append(content);
                        sb.append("\n");
                    }
                    pkcs = sb.toString();
                    if (d != null) {
                        d.close();
                    }
                    pkcs = pkcs.substring(0, pkcs.length() - 1);
                }
            }
        } catch (IOException ee) {
            throw new EBaseException(CMS.getLogMessage("BASE_OPEN_FILE_FAILED"));
        }

        pkcs = pkcs.trim();
        int totalLen = pkcs.length();

        if (pkcs.indexOf(BEGIN_HEADER) != 0 ||
                pkcs.indexOf(END_HEADER) != (totalLen - 25)) {
            throw (new EBaseException(CMS.getLogMessage("BASE_INVALID_CERT_FORMAT")));
        }

        String nickname = "";

        if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
            nickname = getCANewnickname();
        } else if (certType.equals(Constants.PR_RA_SIGNING_CERT)) {
            nickname = getRANewnickname();
        } else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT)) {
            nickname = getKRANewnickname();
        } else if (certType.equals(Constants.PR_SERVER_CERT)) {
            nickname = getAgentNewnickname();
        } else if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
            nickname = getRADMNewnickname();
        } else if (certType.equals(Constants.PR_OTHER_CERT)) {
            nickname = otherNickname;
        } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
            nickname = getOCSPNewnickname();
        }
        if (nickname.equals(""))
            nickname = getNickname(certType);

        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        String content = jssSubSystem.getCertPrettyPrint(pkcs,
                super.getLocale(req));

        if (nickname != null && !nickname.equals(""))
            results.put(Constants.PR_NICKNAME, nickname);
        results.put(Constants.PR_CERT_CONTENT, content);
        //results = jssSubSystem.getCertInfo(value);

        sendResponse(SUCCESS, null, results, resp);
    }

    private void getCertPrettyPrint(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();
        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        String nickname = "";
        String serialno = "";
        String issuername = "";
        Locale locale = super.getLocale(req);
        NameValuePairs pairs = new NameValuePairs();

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(Constants.OP_TYPE))
                continue;
            if (key.equals(Constants.RS_ID))
                continue;
            if (key.equals(Constants.OP_SCOPE))
                continue;
            if (key.equals(Constants.PR_NICK_NAME)) {
                nickname = value;
                continue;
            }
            if (key.equals(Constants.PR_SERIAL_NUMBER)) {
                serialno = value;
                continue;
            }
            if (key.equals(Constants.PR_ISSUER_NAME)) {
                issuername = value;
                continue;
            }
        }

        String print = jssSubSystem.getCertPrettyPrintAndFingerPrint(nickname,
                serialno, issuername, locale);
        pairs.put(nickname, print);

        sendResponse(SUCCESS, null, pairs, resp);
    }

    private void getRootCertTrustBit(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();
        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        String nickname = "";
        String serialno = "";
        String issuername = "";
        NameValuePairs pairs = new NameValuePairs();

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(Constants.OP_TYPE))
                continue;
            if (key.equals(Constants.RS_ID))
                continue;
            if (key.equals(Constants.OP_SCOPE))
                continue;
            if (key.equals(Constants.PR_NICK_NAME)) {
                nickname = value;
                continue;
            }
            if (key.equals(Constants.PR_SERIAL_NUMBER)) {
                serialno = value;
                continue;
            }
            if (key.equals(Constants.PR_ISSUER_NAME)) {
                issuername = value;
                continue;
            }
        }

        String trustbit = jssSubSystem.getRootCertTrustBit(nickname,
                serialno, issuername);
        pairs.put(nickname, trustbit);

        sendResponse(SUCCESS, null, pairs, resp);
    }

    private void getCACerts(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        NameValuePairs pairs = jssSubSystem.getCACerts();

        sendResponse(SUCCESS, null, pairs, resp);
    }

    private void deleteRootCert(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String id = req.getParameter(Constants.RS_ID);
        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        int mindex = id.indexOf(":SERIAL#<");
        String nickname = id.substring(0, mindex);
        String sstr1 = id.substring(mindex);
        int lindex = sstr1.indexOf(">");
        String serialno = sstr1.substring(9, lindex);
        String issuername = sstr1.substring(lindex + 1);
        jssSubSystem.deleteRootCert(nickname, serialno, issuername);
        sendResponse(SUCCESS, null, null, resp);
    }

    private void deleteUserCert(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        String id = req.getParameter(Constants.RS_ID);
        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        int mindex = id.indexOf(":SERIAL#<");
        String nickname = id.substring(0, mindex);
        String sstr1 = id.substring(mindex);
        int lindex = sstr1.indexOf(">");
        String serialno = sstr1.substring(9, lindex);
        String issuername = sstr1.substring(lindex + 1);
        jssSubSystem.deleteUserCert(nickname, serialno, issuername);
        sendResponse(SUCCESS, null, null, resp);
    }

    private void getRootCerts(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        NameValuePairs pairs = jssSubSystem.getRootCerts();

        sendResponse(SUCCESS, null, pairs, resp);
    }

    private void getAllCertsManage(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        NameValuePairs pairs = jssSubSystem.getAllCertsManage();

        sendResponse(SUCCESS, null, pairs, resp);
    }

    private void getUserCerts(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        NameValuePairs pairs = jssSubSystem.getUserCerts();
        sendResponse(SUCCESS, null, pairs, resp);
    }

    private void deleteCerts(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();
        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        String nickname = "";
        String date = "";

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(Constants.OP_TYPE))
                continue;
            if (key.equals(Constants.RS_ID))
                continue;
            if (key.equals(Constants.OP_SCOPE))
                continue;
            int index = value.indexOf(";");

            nickname = value.substring(0, index);
            date = value.substring(index + 1);
            // cant use this one now since jss doesnt have the interface to
            // do it.
            jssSubSystem.deleteCert(nickname, date);
            //            jssSubsystem.deleteCACert(nickname, date);
        }

        sendResponse(SUCCESS, null, null, resp);
    }

    private void validateSubjectName(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(Constants.PR_SUBJECT_NAME)) {
                ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                        CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);

                jssSubSystem.isX500DN(value);
            }
        }

        sendResponse(SUCCESS, null, null, resp);
    }

    private void validateKeyLength(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {

        sendResponse(SUCCESS, null, null, resp);
    }

    private void validateCurveName(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();
        String curveName = null;

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(Constants.PR_KEY_CURVENAME)) {
                curveName = value;
            }
        }
        // check that the curvename is in the list of supported curves
        String curveList = mConfig.getString("keys.ecc.curve.list", "nistp521");
        String[] curves = curveList.split(",");
        boolean match = false;
        for (int i = 0; i < curves.length; i++) {
            if (curves[i].equals(curveName)) {
                match = true;
            }
        }
        if (!match) {
            throw new EBaseException(CMS.getUserMessage("CMS_BASE_INVALID_ECC_CURVE_NAME"));
        }

        sendResponse(SUCCESS, null, null, resp);
    }

    private void validateCertExtension(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();
        String certExt = "";

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(ConfigConstants.PR_CERTIFICATE_EXTENSION)) {
                certExt = value;
                break;
            }
        }

        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);

        jssSubSystem.checkCertificateExt(certExt);
        sendResponse(SUCCESS, null, null, resp);
    }

    private void getSubjectName(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        Enumeration<String> enum1 = req.getParameterNames();

        String nickname = "";

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(Constants.RS_ID)) {
                nickname = getNickname(value);
                break;
            }
        }

        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        String subjectName = jssSubSystem.getSubjectDN(nickname);

        params.put(Constants.PR_SUBJECT_NAME, subjectName);
        sendResponse(SUCCESS, null, params, resp);
    }

    private void processSubjectName(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        NameValuePairs params = new NameValuePairs();
        Enumeration<String> enum1 = req.getParameterNames();

        String nickname = "";

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(Constants.PR_NICKNAME)) {
                nickname = value;
            }
        }

        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        String subjectName = jssSubSystem.getSubjectDN(nickname);

        params.put(Constants.PR_SUBJECT_NAME, subjectName);
        sendResponse(SUCCESS, null, params, resp);
    }

    public void setRootCertTrust(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String nickname = req.getParameter(Constants.PR_NICK_NAME);
        String serialno = req.getParameter(Constants.PR_SERIAL_NUMBER);
        String issuername = req.getParameter(Constants.PR_ISSUER_NAME);
        String trust = req.getParameter("trustbit");

        CMS.debug("CMSAdminServlet: setRootCertTrust()");

        ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
        try {
            jssSubSystem.setRootCertTrust(nickname, serialno, issuername, trust);
        } catch (EBaseException e) {
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);
            // rethrow the specific exception to be handled later
            throw e;
        }

        // store a message in the signed audit log file
        auditMessage = CMS.getLogMessage(
                    LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                    auditSubjectID,
                    ILogger.SUCCESS,
                    auditParams(req));

        audit(auditMessage);

        sendResponse(SUCCESS, null, null, resp);
    }

    /**
     * Establish trust of a CA certificate
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY used when "Manage Certificate" is used to edit
     * the trustness of certs and deletion of certs
     * </ul>
     *
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException failed to establish CA certificate trust
     */
    private void trustCACert(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        CMS.debug("CMSAdminServlet: trustCACert()");

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            Enumeration<String> enum1 = req.getParameterNames();
            ICryptoSubsystem jssSubSystem = (ICryptoSubsystem)
                    CMS.getSubsystem(CMS.SUBSYSTEM_CRYPTO);
            String trust = "";

            while (enum1.hasMoreElements()) {
                String key = enum1.nextElement();
                String value = req.getParameter(key);

                if (key.equals(Constants.RS_ID)) {
                    trust = value;
                } else if (key.equals("certName0")) {
                    int index = value.indexOf(";");
                    String nickname = value.substring(0, index);
                    String date = value.substring(index + 1);

                    jssSubSystem.trustCert(nickname, date, trust);
                }
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            audit(auditMessage);

            //sendResponse(SUCCESS, null, null, resp);
            sendResponse(RESTART, null, null, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
            // } catch( ServletException eAudit3 ) {
            //     // store a message in the signed audit log file
            //     auditMessage = CMS.getLogMessage(
            //                        LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY,
            //                        auditSubjectID,
            //                        ILogger.FAILURE,
            //                        auditParams( req ) );
            //
            //     audit( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    /**
     * Execute all self tests specified to be run on demand.
     * <P>
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION used when self tests are run on demand
     * </ul>
     *
     * @exception EMissingSelfTestException a self test plugin instance
     *                property name was missing
     * @exception ESelfTestException a self test is missing a required
     *                configuration parameter
     * @exception IOException an input/output error has occurred
     */
    private synchronized void
            runSelfTestsOnDemand(HttpServletRequest req,
                    HttpServletResponse resp)
                    throws EMissingSelfTestException,
                    ESelfTestException,
                    IOException {
        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            if (CMS.debugOn()) {
                CMS.debug("CMSAdminServlet::runSelfTestsOnDemand():"
                        + "  ENTERING . . .");
            }
            Enumeration<String> enum1 = req.getParameterNames();
            String request = "";
            NameValuePairs results = new NameValuePairs();
            String content = "";
            String instanceName = null;
            String instanceFullName = null;
            String logMessage = null;

            while (enum1.hasMoreElements()) {
                String key = enum1.nextElement();
                String value = req.getParameter(key);

                if (key.equals(Constants.PR_RUN_SELFTESTS_ON_DEMAND)) {
                    request = value;
                }
            }

            ISelfTestSubsystem mSelfTestSubsystem = (ISelfTestSubsystem)
                    CMS.getSubsystem(CMS.SUBSYSTEM_SELFTESTS);

            if ((request == null) ||
                    (request.equals(""))) {
                // self test plugin run on demand request parameter was missing
                // log the error
                logMessage = CMS.getLogMessage("SELFTESTS_RUN_ON_DEMAND_REQUEST",
                            getServletInfo(),
                            Constants.PR_RUN_SELFTESTS_ON_DEMAND
                        );

                mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                        logMessage);

                // store a message in the signed audit log file
                auditMessage = CMS.getLogMessage(
                            LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                            auditSubjectID,
                            ILogger.FAILURE);

                audit(auditMessage);

                // notify console of FAILURE
                content += logMessage
                        + "\n";
                sendResponse(ERROR, content, null, resp);

                // raise an exception
                throw new ESelfTestException(logMessage);
            }

            // run all self test plugin instances (designated on-demand)
            String[] selftests = mSelfTestSubsystem.listSelfTestsEnabledOnDemand();

            if (selftests != null && selftests.length > 0) {
                // log that execution of on-demand self tests has begun
                logMessage = CMS.getLogMessage("SELFTESTS_RUN_ON_DEMAND",
                            getServletInfo());

                mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                        logMessage);

                // store this information for console notification
                content += logMessage
                        + "\n";

                for (int i = 0; i < selftests.length; i++) {
                    if (selftests[i] != null) {
                        instanceName = selftests[i].trim();
                        instanceFullName = ISelfTestSubsystem.ID
                                + "."
                                + ISelfTestSubsystem.PROP_CONTAINER
                                + "."
                                + ISelfTestSubsystem.PROP_INSTANCE
                                + "."
                                + instanceName;
                    } else {
                        // self test plugin instance property name was missing
                        // log the error
                        logMessage = CMS.getLogMessage(
                                    "SELFTESTS_PARAMETER_WAS_NULL",
                                    getServletInfo());

                        mSelfTestSubsystem.log(
                                mSelfTestSubsystem.getSelfTestLogger(),
                                logMessage);

                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                                    auditSubjectID,
                                    ILogger.FAILURE);

                        audit(auditMessage);

                        // notify console of FAILURE
                        content += logMessage
                                + "\n";
                        sendResponse(ERROR, content, null, resp);

                        // raise an exception
                        throw new EMissingSelfTestException();
                    }

                    ISelfTest test = mSelfTestSubsystem.getSelfTest(instanceName);

                    if (test == null) {
                        // self test plugin instance property name is not present
                        // log the error
                        logMessage = CMS.getLogMessage("SELFTESTS_MISSING_NAME",
                                    getServletInfo(),
                                    instanceFullName);

                        mSelfTestSubsystem.log(
                                mSelfTestSubsystem.getSelfTestLogger(),
                                logMessage);

                        // store a message in the signed audit log file
                        auditMessage = CMS.getLogMessage(
                                    LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                                    auditSubjectID,
                                    ILogger.FAILURE);

                        audit(auditMessage);

                        // notify console of FAILURE
                        content += logMessage
                                + "\n";
                        sendResponse(ERROR, content, null, resp);

                        // raise an exception
                        throw new EMissingSelfTestException(instanceFullName);
                    }

                    try {
                        if (CMS.debugOn()) {
                            CMS.debug("CMSAdminServlet::runSelfTestsOnDemand():"
                                    + "    running \""
                                    + test.getSelfTestName()
                                    + "\"");
                        }

                        // store this information for console notification
                        content += "CMSAdminServlet::runSelfTestsOnDemand():"
                                + "    running \""
                                + test.getSelfTestName()
                                + "\" . . .\n";

                        test.runSelfTest(mSelfTestSubsystem.getSelfTestLogger());

                        // store this information for console notification
                        content += "COMPLETED SUCCESSFULLY\n";
                    } catch (ESelfTestException e) {
                        // Check to see if the self test was critical:
                        if (mSelfTestSubsystem.isSelfTestCriticalOnDemand(
                                instanceName)) {
                            // log the error
                            logMessage = CMS.getLogMessage(
                                        "SELFTESTS_RUN_ON_DEMAND_FAILED",
                                        getServletInfo(),
                                        instanceFullName);

                            mSelfTestSubsystem.log(
                                    mSelfTestSubsystem.getSelfTestLogger(),
                                    logMessage);

                            // store a message in the signed audit log file
                            auditMessage = CMS.getLogMessage(
                                        LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                                        auditSubjectID,
                                        ILogger.FAILURE);

                            audit(auditMessage);

                            // notify console of FAILURE
                            content += "FAILED WITH CRITICAL ERROR\n";
                            content += logMessage
                                    + "\n";
                            sendResponse(ERROR, content, null, resp);

                            // shutdown the system gracefully
                            CMS.shutdown();

                            return;
                        } else {
                            // store this information for console notification
                            content += "FAILED WITH NON-CRITICAL ERROR\n";
                        }
                    }
                }

                // log that execution of all "critical" on-demand self tests
                // has completed "successfully"
                logMessage = CMS.getLogMessage("SELFTESTS_RUN_ON_DEMAND_SUCCEEDED",
                            getServletInfo());
                mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                        logMessage);

                // store this information for console notification
                content += logMessage
                        + "\n";
            } else {
                // log this fact
                logMessage = CMS.getLogMessage("SELFTESTS_NOT_RUN_ON_DEMAND",
                            getServletInfo());

                mSelfTestSubsystem.log(mSelfTestSubsystem.getSelfTestLogger(),
                        logMessage);

                // store this information for console notification
                content += logMessage
                        + "\n";
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                        auditSubjectID,
                        ILogger.SUCCESS);

            audit(auditMessage);

            // notify console of SUCCESS
            results.put(Constants.PR_RUN_SELFTESTS_ON_DEMAND_CLASS,
                    CMSAdminServlet.class.getName());
            results.put(Constants.PR_RUN_SELFTESTS_ON_DEMAND_CONTENT,
                    content);
            sendResponse(SUCCESS, null, results, resp);

            if (CMS.debugOn()) {
                CMS.debug("CMSAdminServlet::runSelfTestsOnDemand():"
                        + "  EXITING.");
            }
        } catch (EMissingSelfTestException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                        auditSubjectID,
                        ILogger.FAILURE);

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (ESelfTestException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                        auditSubjectID,
                        ILogger.FAILURE);

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
        } catch (IOException eAudit3) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        LOGGING_SIGNED_AUDIT_SELFTESTS_EXECUTION,
                        auditSubjectID,
                        ILogger.FAILURE);

            audit(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit3;
        }
    }

    public void log(int level, String msg) {
        mLogger.log(ILogger.EV_SYSTEM, ILogger.S_OTHER, level, "CMSAdminServlet: " + msg);
    }

    /**
     * Signed Audit Log Public Key
     *
     * This method is called to obtain the public key from the passed in
     * "KeyPair" object for a signed audit log message.
     * <P>
     *
     * @param object a Key Pair Object
     * @return key string containing the public key
     */
    private String auditPublicKey(KeyPair object) {
        // if no signed audit object exists, bail
        if (mSignedAuditLogger == null) {
            return null;
        }

        if (object == null) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        byte rawData[] = null;

        rawData = object.getPublic().getEncoded();

        String key = null;
        StringBuffer sb = new StringBuffer();

        // convert "rawData" into "base64Data"
        if (rawData != null) {
            String base64Data = null;

            base64Data = Utils.base64encode(rawData).trim();

            // extract all line separators from the "base64Data"
            for (int i = 0; i < base64Data.length(); i++) {
                if (base64Data.substring(i, i).getBytes() != EOL) {
                    sb.append(base64Data.substring(i, i));
                }
            }
        }
        key = sb.toString();

        if (key != null) {
            key = key.trim();

            if (key.equals("")) {
                return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
            } else {
                return key;
            }
        } else {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }
    }
}
