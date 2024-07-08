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
import java.security.KeyPair;
import java.util.Date;
import java.util.Enumeration;
import java.util.Locale;
import java.util.StringTokenizer;

import jakarta.servlet.ServletConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.dogtagpki.util.cert.CertUtil;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.NotInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.PQGParams;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Cert;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.symkey.SessionKey;
import org.mozilla.jss.util.ConsolePasswordCallback;
import org.mozilla.jss.util.PasswordCallback;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.certsrv.logging.AuditEvent;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.event.ConfigTrustedPublicKeyEvent;
import com.netscape.certsrv.selftests.EMissingSelfTestException;
import com.netscape.certsrv.selftests.ESelfTestException;
import com.netscape.cms.selftests.SelfTest;
import com.netscape.cmscore.apps.CMS;
import com.netscape.cmscore.apps.CMSEngine;
import com.netscape.cmscore.apps.DatabaseConfig;
import com.netscape.cmscore.apps.EngineConfig;
import com.netscape.cmscore.base.ConfigStore;
import com.netscape.cmscore.ldapconn.LDAPConfig;
import com.netscape.cmscore.logging.Auditor;
import com.netscape.cmscore.security.JssSubsystem;
import com.netscape.cmscore.selftests.SelfTestSubsystem;
import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * A class representings an administration servlet. This
 * servlet is responsible to serve Certificate Server
 * level administrative operations such as configuration
 * parameter updates.
 *
 * @version $Revision$, $Date$
 */
public class CMSAdminServlet extends AdminServlet {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CMSAdminServlet.class);

    private static final long serialVersionUID = 714370238027440050L;
    private final static String INFO = "CMSAdminServlet";

    private final static String PROP_SMTP = "smtp";

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
    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }

    /**
     * Returns serlvet information.
     */
    @Override
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Serves HTTP request.
     */
    @Override
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
                getEnv(resp);
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
                    readSMTPConfig(resp);
                else if (scope.equals(ScopeDef.SC_STAT))
                    readStat(resp);
                else if (scope.equals(ScopeDef.SC_ENCRYPTION))
                    readEncryption(resp);
                else if (scope.equals(ScopeDef.SC_TOKEN))
                    getAllTokenNames(resp);
                else if (scope.equals(ScopeDef.SC_SUBJECT_NAME))
                    getSubjectName(req, resp);
                else if (scope.equals(ScopeDef.SC_GET_NICKNAMES))
                    getAllNicknames(resp);
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
                    readSubsystem(resp);
                else if (scope.equals(ScopeDef.SC_CA_CERTLIST))
                    getCACerts(resp);
                else if (scope.equals(ScopeDef.SC_ALL_CERTLIST))
                    getAllCertsManage(resp);
                else if (scope.equals(ScopeDef.SC_USERCERTSLIST))
                    getUserCerts(resp);
                else if (scope.equals(ScopeDef.SC_TKSKEYSLIST))
                    getTKSKeys(req, resp);
                else if (scope.equals(ScopeDef.SC_TOKEN))
                    getAllTokenNames(resp);
                else if (scope.equals(ScopeDef.SC_ROOTCERTSLIST))
                    getRootCerts(resp);
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
                    validateKeyLength(resp);
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

    private void getEnv(HttpServletResponse resp) throws IOException {
        NameValuePairs params = new NameValuePairs();

        if (File.separator.equals("\\"))
            params.put(Constants.PR_NT, Constants.TRUE);
        else
            params.put(Constants.PR_NT, Constants.FALSE);

        sendResponse(SUCCESS, null, params, resp);
    }

    private void getAllTokenNames(HttpServletResponse resp) throws IOException, EBaseException {

        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_TOKEN_LIST, jssSubsystem.getTokenList());

        sendResponse(SUCCESS, null, params, resp);
    }

    private void getAllNicknames(HttpServletResponse resp) throws IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        params.put(Constants.PR_ALL_NICKNAMES, jssSubsystem.getAllCerts());

        sendResponse(SUCCESS, null, params, resp);
    }

    public boolean isSubsystemInstalled(String subsystem) {
        return false;
    }

    public void readEncryption(NameValuePairs params) throws EBaseException {
    }

    private void readEncryption(HttpServletResponse resp) throws IOException, EBaseException {

        CMSEngine engine = getCMSEngine();

        JssSubsystem jssSubsystem = engine.getJSSSubsystem();

        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_CIPHER_VERSION, jssSubsystem.getCipherVersion());
        params.put(Constants.PR_CIPHER_FORTEZZA, jssSubsystem.isCipherFortezza());
        params.put(Constants.PR_CIPHER_PREF, jssSubsystem.getCipherPreferences());

        String tokenList = jssSubsystem.getTokenList();

        String tokenNewList = "";
        StringTokenizer tokenizer = new StringTokenizer(tokenList, ",");

        while (tokenizer.hasMoreElements()) {
            String tokenName = (String) tokenizer.nextElement();
            String certs = jssSubsystem.getCertListWithoutTokenName(tokenName);

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

        readEncryption(params);

        String nickName = engine.getServerCertNickname();

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

    public String getCertNickname(String nickName) {
        if (!nickName.equals("")) {
            StringTokenizer tokenizer = new StringTokenizer(nickName, ":");
            String tokenName = "";

            if (tokenizer.countTokens() > 1) {
                tokenName = (String) tokenizer.nextElement();
            } else {
                tokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
            }
            return tokenName + "," + ((String) tokenizer.nextElement());
        }
        return "";
    }

    public void modifyCACert(HttpServletRequest request, String value) throws EBaseException {
    }

    public void modifyKRACert(String nickname) throws EBaseException {
    }

    public void modifyServerCert(String nickname) throws EBaseException {
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
    private void modifyEncryption(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            Enumeration<String> enum1 = req.getParameterNames();
            NameValuePairs params = new NameValuePairs();
            JssSubsystem jssSubsystem = engine.getJSSSubsystem();
            jssSubsystem.getInternalTokenName();

            while (enum1.hasMoreElements()) {
                String name = enum1.nextElement();
                String val = req.getParameter(name);

                if (name.equals(Constants.PR_CIPHER_PREF)) {
                    jssSubsystem.setCipherPreferences(val);
                } else if (name.equals(Constants.PR_CERT_CA)) {
                    if ((val != null) && (!val.equals(""))) {
                        modifyCACert(req, val);
                    }
                } else if (name.equals(Constants.PR_CERT_TRANS)) {
                    if ((val != null) && (!val.equals(""))) {
                        String nickName = getCertConfigNickname(val);
                        modifyKRACert(nickName);
                    }
                } else if (name.equals(Constants.PR_CERT_SERVER)) {
                    if ((val != null) && (!val.equals(""))) {
                        String nickName = getCertConfigNickname(val);

                        modifyRADMCert(nickName);
                        modifyAgentGatewayCert(nickName);
                        modifyServerCert(nickName);
                    }
                }
            }

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_ENCRYPTION,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req));

            auditor.log(auditMessage);

            sendResponse(RESTART, null, params, resp);
            mConfig.commit(true);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_ENCRYPTION,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            auditor.log(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.CONFIG_ENCRYPTION,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req));

            auditor.log(auditMessage);

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
            //     auditor.log( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    public String getCertConfigNickname(String val) throws EBaseException {
        StringTokenizer tokenizer = new StringTokenizer(val, ",");

        if (tokenizer.countTokens() != 2) {
            throw new EBaseException(CMS.getLogMessage("BASE_INVALID_UI_INFO"));
        }
        String tokenName = (String) tokenizer.nextElement();

        if (CryptoUtil.isInternalToken(tokenName))
            tokenName = "";
        else
            tokenName = tokenName + ":";
        return (tokenName + (String) tokenizer.nextElement());
    }

    public void modifyRADMCert(String nickName) {
        CMSEngine engine = getCMSEngine();
        engine.setServerCertNickname(nickName);

        /*
         RemoteAdmin raAdmin = (RemoteAdmin)RemoteAdmin.getInstance();
         HTTPService httpsService = raAdmin.getHttpsService();
         httpsService.setNickName(nickName);
         */
    }

    public void modifyAgentGatewayCert(String nickName) {
        CMSEngine engine = getCMSEngine();
        engine.setServerCertNickname(nickName);

        /*
         AgentGateway gateway = (AgentGateway)mReg.get(AgentGateway.ID);
         HTTPService httpsService = gateway.getHttpsService();
         httpsService.setNickName(nickName);
         */
    }

    public void modifyCAGatewayCert(String nickname) {
    }

    /**
     * Performs Server Tasks: RESTART/STOP operation
     */
    private void performTasks(HttpServletRequest req, HttpServletResponse resp) throws IOException {
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
            logger.debug("CMSAdminServlet.performTasks(): shutdown server");
            CMSEngine engine = getCMSEngine();
            engine.shutdown();
            return;
        }

        sendResponse(ERROR, "Unknown operation", null, resp);

    }

    void readSubsystem(NameValuePairs params) {
    }

    /**
     * Reads subsystems that server has loaded with.
     */
    private void readSubsystem(HttpServletResponse resp) throws IOException {

        NameValuePairs params = new NameValuePairs();
        readSubsystem(params);

        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Reads server statistics.
     */
    private void readStat(HttpServletResponse resp) throws IOException {
        NameValuePairs params = new NameValuePairs();
        CMSEngine engine = getCMSEngine();
        EngineConfig cs = engine.getConfig();
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
            String instanceId = CMS.getInstanceID();
            params.put(Constants.PR_STAT_INSTANCEID, instanceId);
        } catch (Exception e) {
        }

        params.put(Constants.PR_STAT_STARTUP,
                (new Date(engine.getStartupTime())).toString());
        params.put(Constants.PR_STAT_TIME,
                (new Date(System.currentTimeMillis())).toString());
        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Modifies database information.
     */
    private void setDBConfig(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {

        LDAPConfig dbConfig = mConfig.getInternalDBConfig();
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
    private void createMasterKey(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {

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

        CMSEngine engine = getCMSEngine();
        EngineConfig cs = engine.getConfig();

        if (selectedToken != null && newKeyName != null) {
            SessionKey.GenMasterKey(selectedToken, newKeyName); // check for errors
            cs.putString("tks.defaultSlot", selectedToken);
            String masterKeyPrefix = cs.getString("tks.master_key_prefix", null);

            SessionKey.SetDefaultPrefix(masterKeyPrefix);
            params.put(Constants.PR_KEY_LIST, newKeyName);
            params.put(Constants.PR_TOKEN_LIST, selectedToken);
        }
        sendResponse(SUCCESS, null, params, resp);
    }

    /**
     * Reads secmod.db
     */
    private void getTKSKeys(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {

        NameValuePairs params = new NameValuePairs();
        Enumeration<String> e = req.getParameterNames();

        CMSEngine engine = getCMSEngine();

        while (e.hasMoreElements()) {
            String name = e.nextElement();

            if (name.equals(Constants.PR_TOKEN_LIST)) {
                String selectedToken = req.getParameter(name);

                JssSubsystem jssSubsystem = engine.getJSSSubsystem();

                CryptoToken token = null;

                if (!jssSubsystem.isTokenLoggedIn(selectedToken)) {
                    PasswordCallback cpcb = new ConsolePasswordCallback();
                    while (true) {
                        try {
                            token = CryptoUtil.getKeyStorageToken(selectedToken);
                            token.login(cpcb);
                            break;
                        } catch (Exception e3) {
                            // logger.warn(CMS.getLogMessage("CMSCORE_SECURITY_INCORRECT_PWD"), e3);
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
    private void getDBConfig(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {
        DatabaseConfig dbConfig = mConfig.getDatabaseConfig();
        ConfigStore ldapConfig = dbConfig.getSubStore("ldap", ConfigStore.class);
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
    private void modifySMTPConfig(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {
        ConfigStore sConfig = mConfig.getSubStore(PROP_SMTP, ConfigStore.class);

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
    private void readSMTPConfig(HttpServletResponse resp) throws IOException, EBaseException {
        ConfigStore dbConfig = mConfig.getSubStore(PROP_SMTP, ConfigStore.class);
        NameValuePairs params = new NameValuePairs();

        params.put(Constants.PR_SERVER_NAME,
                dbConfig.getString("host"));
        params.put(Constants.PR_PORT,
                dbConfig.getString("port"));
        sendResponse(SUCCESS, null, params, resp);
    }

    private void loggedInToken(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {
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

        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        jssSubsystem.loggedInToken(tokenName, pwd);

        /* Do a "PUT" of the new pw to the watchdog" */
        engine.putPasswordCache(tokenName, pwd);
        sendResponse(SUCCESS, null, null, resp);
    }

    private void checkTokenStatus(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {
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

        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        boolean status = jssSubsystem.isTokenLoggedIn(value);

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
    private void getCertRequest(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();
        String auditPublicKey = ILogger.SIGNED_AUDIT_EMPTY_VALUE;

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            NameValuePairs params = new NameValuePairs();
            Enumeration<String> enum1 = req.getParameterNames();
            String tokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
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
                    if (!CryptoUtil.isInternalToken(value))
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

            pathname = CMS.getInstanceDir() + File.separator + "conf" + File.separator;
            dir = pathname;

            JssSubsystem jssSubsystem = engine.getJSSSubsystem();

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

            CryptoToken token;
            try {
                token = CryptoUtil.getKeyStorageToken(tokenName);
            } catch (NotInitializedException | NoSuchTokenException e) {
                throw new EBaseException("Unable to find token: " + tokenName, e);
            }

            if (keyType.equals("")) {
                if (nickname.equals("")) {
                    // store a message in the signed audit log file
                    auditMessage = CMS.getLogMessage(
                                AuditEvent.KEY_GEN_ASYMMETRIC,
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditPublicKey);

                    auditor.log(auditMessage);

                    throw new EBaseException(
                            CMS.getLogMessage("BASE_CERT_NOT_FOUND"));
                }
                keypair = jssSubsystem.getKeyPair(nickname);
            } else {
                if (keyType.equals("ECC")) {
                    // get ECC keypair
                    keypair = jssSubsystem.getECCKeyPair(token, keyCurveName, certType);
                } else { //DSA or RSA
                    if (keyType.equals("DSA"))
                        pqgParams = jssSubsystem.getPQG(keyLength);
                    keypair = jssSubsystem.getKeyPair(token, keyType, keyLength, pqgParams);
                }
            }

            // reset the "auditPublicKey"
            auditPublicKey = auditPublicKey(keypair);

            if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                pathname = pathname + File.separator + "cacsr.txt";
                if (!keyType.equals(""))
                    setCANewnickname(tokenName, nicknameWithoutTokenName);
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
            String certReq = jssSubsystem.getCertRequest(subjectName, keypair);

            params.put(Constants.PR_CSR, certReq);
            params.put(Constants.PR_CERT_REQUEST_DIR, dir);
            PrintStream ps = new PrintStream(new FileOutputStream(pathname));

            ps.println(certReq);
            ps.close();

            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.KEY_GEN_ASYMMETRIC,
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditPublicKey);

            auditor.log(auditMessage);

            mConfig.commit(true);
            sendResponse(SUCCESS, null, params, resp);
        } catch (EBaseException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.KEY_GEN_ASYMMETRIC,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditPublicKey);

            auditor.log(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.KEY_GEN_ASYMMETRIC,
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditPublicKey);

            auditor.log(auditMessage);

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
            //     auditor.log( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    String getCANewnickname() throws EBaseException {
        return null;
    }

    void setCANewnickname(String tokenName, String nickname) throws EBaseException {
    }

    void setOCSPNewnickname(String tokenName, String nickname) throws EBaseException {
    }

    String getOCSPNewnickname() throws EBaseException {
        return null;
    }

    String getKRANewnickname() throws EBaseException {
        return null;
    }

    void setKRANewnickname(String tokenName, String nickname) throws EBaseException {
    }

    String getKRANickname() throws EBaseException {
        return null;
    }

    void setKRANickname(String nickname) throws EBaseException {
    }

    private void setRADMNewnickname(String tokenName, String nickName) {
        CMSEngine engine = getCMSEngine();
        engine.setServerCertNickname(tokenName, nickName);

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

    private String getRADMNewnickname() {
        // assuming the nickname does not change.
        CMSEngine engine = getCMSEngine();
        return engine.getServerCertNickname();

        /*
         RemoteAdmin raAdmin = (RemoteAdmin)RemoteAdmin.getInstance();
         HTTPService httpsService = raAdmin.getHttpsService();
         return httpsService.getNewNickName();
         */
    }

    private void setAgentNewnickname(String tokenName, String nickName) {
        CMSEngine engine = getCMSEngine();
        engine.setServerCertNickname(tokenName, nickName);

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

    private String getAgentNewnickname() {
        // assuming the nickname does not change.
        CMSEngine engine = getCMSEngine();
        return engine.getServerCertNickname();

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
    public void issueImportCert(HttpServletRequest req,
            HttpServletResponse resp) throws ServletException,
            IOException, EBaseException {
    }

    public void installCASigningCert(
            String fullName,
            String nickname,
            String tokenName
            ) throws EBaseException {
    }

    public void installOCSPSigningCert(
            String fullName,
            String nickname,
            String tokenName
            ) throws EBaseException {
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
    private void installCert(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            String tokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
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

            logger.debug("CMSAdminServlet: installCert(" + nickname + ")");

            try {
                if (pkcs == null || pkcs.equals("")) {
                    if (certpath == null || certpath.equals("")) {

                        auditor.log(new ConfigTrustedPublicKeyEvent(
                                auditSubjectID,
                                ILogger.FAILURE,
                                auditParams(req)));

                        EBaseException ex = new EBaseException(
                                CMS.getLogMessage("BASE_INVALID_FILE_PATH"));

                        throw ex;
                    }
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
            } catch (IOException ee) {

                auditor.log(new ConfigTrustedPublicKeyEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

                throw new EBaseException(
                        CMS.getLogMessage("BASE_OPEN_FILE_FAILED"));
            }

            pkcs = pkcs.trim();
            pathname = serverRoot + File.separator + serverID
                     + File.separator + "config" + File.separator + pathname;

            JssSubsystem jssSubsystem = engine.getJSSSubsystem();
            //String nickname = getNickname(certType);
            String nicknameWithoutTokenName = "";

            int index = nickname.indexOf(":");

            if (index == -1)
                nicknameWithoutTokenName = nickname;
            else if (index > 0 && (index < (nickname.length() - 1))) {
                tokenName = nickname.substring(0, index);
                nicknameWithoutTokenName = nickname.substring(index + 1);
            } else {

                auditor.log(new ConfigTrustedPublicKeyEvent(
                            auditSubjectID,
                            ILogger.FAILURE,
                            auditParams(req)));

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

            logger.debug("CMSAdminServlet.installCert(): About to try jssSubSystem.importCert: "
                    + nicknameWithoutTokenName);
            try {
                jssSubsystem.importCert(pkcs, nicknameWithoutTokenName,
                        certType);
            } catch (EBaseException e) {

                boolean certFound = false;

                String eString = e.toString();
                if (eString.contains("Failed to find certificate that was just imported")) {
                    logger.debug("CMSAdminServlet.installCert(): nickname="
                            + nicknameWithoutTokenName + " TokenException: " + eString);

                    X509Certificate cert = null;
                    try {
                        cert = CryptoManager.getInstance().findCertByNickname(nickname);
                        if (cert != null) {
                            certFound = true;
                        }
                        logger.debug("CMSAdminServlet.installCert() Found cert just imported: " + nickname);
                    } catch (Exception ex) {
                        logger.warn("CMSAdminServlet.installCert() Can't find cert just imported: " + ex.toString());
                    }
                }

                if (!certFound) {
                    // if it fails, let use a different nickname to try
                    Date now = new Date();
                    String newNickname = nicknameWithoutTokenName + "-" +
                                     now.getTime();

                    jssSubsystem.importCert(pkcs, newNickname, certType);
                    nicknameWithoutTokenName = newNickname;
                    if (tokenName.equals(CryptoUtil.INTERNAL_TOKEN_NAME)) {
                        nickname = newNickname;
                    } else {
                        nickname = tokenName + ":" + newNickname;
                    }
                    logger.debug("CMSAdminServlet: installCert():  After second install attempt following initial error: nickname="
                            + nickname);
                }
            }

            String tokenname1 = nickname.substring(0, index);

            if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
                installCASigningCert(nickname, nicknameWithoutTokenName, tokenname1);

            } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
                installOCSPSigningCert(nickname, nicknameWithoutTokenName, tokenname1);

            } else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT)) {
                setKRANewnickname("", "");
                setKRANickname(nickname);
            } else if (certType.equals(Constants.PR_SERVER_CERT)) {
                setAgentNewnickname("", "");
                //modifyRADMCert(nickname);
                modifyAgentGatewayCert(nickname);
                modifyCAGatewayCert(nickname);
            } else if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
                setRADMNewnickname("", "");
                modifyRADMCert(nickname);
            }

            boolean verified = false;
            try {
                logger.debug("CMSAdminServlet: verifying system certificate " + nickname);
                CertUtil.verifyCertificateUsage(nickname, null);
                verified = true;

                auditMessage = CMS.getLogMessage(
                        AuditEvent.CIMC_CERT_VERIFICATION,
                        auditSubjectID,
                        ILogger.SUCCESS,
                                nickname);

                auditor.log(auditMessage);

            } catch (Exception e) {
                logger.error("CMSAdminServlet: Unable to verify system certificate: " + e.getMessage(), e);
                auditMessage = CMS.getLogMessage(
                                AuditEvent.CIMC_CERT_VERIFICATION,
                                auditSubjectID,
                                ILogger.FAILURE,
                                nickname);

                auditor.log(auditMessage);
            }

            auditor.log(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req)));

            mConfig.commit(true);
            if (verified == true) {
                sendResponse(SUCCESS, null, null, resp);
            } else {
                sendResponse(ERROR, CMS.getUserMessage(getLocale(req), "CMS_ADMIN_SRVLT_CERT_VALIDATE_FAILED"),
                        null, resp);
            }
        } catch (EBaseException eAudit1) {

            auditor.log(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {

            auditor.log(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

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
            //     auditor.log( auditMessage );
            //
            //     // rethrow the specific exception to be handled later
            //     throw eAudit3;
        }
    }

    /**
     * For "importing" cross-signed cert into internal db for further
     * cross pair matching and publishing
     *
     * <ul>
     * <li>signed.audit LOGGING_SIGNED_AUDIT_CONFIG_TRUSTED_PUBLIC_KEY
     * used when "Certificate Setup Wizard" is used to
     * import a CA cross-signed certificate into the database
     * </ul>
     *
     * @exception ServletException a servlet error has occurred
     * @exception IOException an input/output error has occurred
     * @exception EBaseException failed to import a cross-certificate pair
     */
    protected void importXCert(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException, EBaseException {
    }

    String getCANickname() {
        return null;
    }

    String getOCSPNickname() {
        return null;
    }

    public String getNickname(String certType) throws EBaseException {
        String nickname = "";
        CMSEngine engine = getCMSEngine();

        if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
            nickname = getCANickname();
        } else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
            nickname = getOCSPNickname();
        } else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT)) {
            nickname = getKRANickname();
        } else if (certType.equals(Constants.PR_SERVER_CERT)) {
            nickname = engine.getServerCertNickname();
        } else if (certType.equals(Constants.PR_SERVER_CERT_RADM)) {
            nickname = engine.getServerCertNickname();
        }

        return nickname;
    }

    private void getCertInfo(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {
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
                }
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
        } catch (IOException ee) {
            throw new EBaseException(CMS.getLogMessage("BASE_OPEN_FILE_FAILED"));
        }

        pkcs = pkcs.trim();
        int totalLen = pkcs.length();

        if (pkcs.indexOf(Cert.HEADER) != 0 ||
                pkcs.indexOf(Cert.FOOTER) != (totalLen - 25)) {
            throw (new EBaseException(CMS.getLogMessage("BASE_INVALID_CERT_FORMAT")));
        }

        String nickname = "";

        if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
            nickname = getCANewnickname();
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

        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        String content = jssSubsystem.getCertPrettyPrint(pkcs,
                super.getLocale(req));

        if (nickname != null && !nickname.equals(""))
            results.put(Constants.PR_NICKNAME, nickname);
        results.put(Constants.PR_CERT_CONTENT, content);
        //results = jssSubSystem.getCertInfo(value);

        sendResponse(SUCCESS, null, results, resp);
    }

    private void getCertPrettyPrint(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();
        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
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

        String print = jssSubsystem.getCertPrettyPrintAndFingerPrint(nickname,
                serialno, issuername, locale);
        pairs.put(nickname, print);

        sendResponse(SUCCESS, null, pairs, resp);
    }

    private void getRootCertTrustBit(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();
        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
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

        String trustbit = jssSubsystem.getRootCertTrustBit(nickname,
                serialno, issuername);
        pairs.put(nickname, trustbit);

        sendResponse(SUCCESS, null, pairs, resp);
    }

    private void getCACerts(HttpServletResponse resp) throws IOException, EBaseException {

        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        NameValuePairs pairs = jssSubsystem.getCACerts();

        sendResponse(SUCCESS, null, pairs, resp);
    }

    private void deleteRootCert(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {

        String id = req.getParameter(Constants.RS_ID);
        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        int mindex = id.indexOf(":SERIAL#<");
        String nickname = id.substring(0, mindex);
        String sstr1 = id.substring(mindex);
        int lindex = sstr1.indexOf(">");
        String serialno = sstr1.substring(9, lindex);
        String issuername = sstr1.substring(lindex + 1);
        jssSubsystem.deleteRootCert(nickname, serialno, issuername);
        sendResponse(SUCCESS, null, null, resp);
    }

    private void deleteUserCert(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {

        String id = req.getParameter(Constants.RS_ID);
        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        int mindex = id.indexOf(":SERIAL#<");
        String nickname = id.substring(0, mindex);
        String sstr1 = id.substring(mindex);
        int lindex = sstr1.indexOf(">");
        String serialno = sstr1.substring(9, lindex);
        String issuername = sstr1.substring(lindex + 1);
        jssSubsystem.deleteUserCert(nickname, serialno, issuername);
        sendResponse(SUCCESS, null, null, resp);
    }

    private void getRootCerts(HttpServletResponse resp) throws IOException, EBaseException {
        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        NameValuePairs pairs = jssSubsystem.getRootCerts();

        sendResponse(SUCCESS, null, pairs, resp);
    }

    private void getAllCertsManage(HttpServletResponse resp) throws IOException, EBaseException {
        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        NameValuePairs pairs = jssSubsystem.getAllCertsManage();

        sendResponse(SUCCESS, null, pairs, resp);
    }

    private void getUserCerts(HttpServletResponse resp) throws IOException, EBaseException {
        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        NameValuePairs pairs = jssSubsystem.getUserCerts();
        sendResponse(SUCCESS, null, pairs, resp);
    }

    private void deleteCerts(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {
        Enumeration<String> enum1 = req.getParameterNames();
        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
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
            jssSubsystem.deleteCert(nickname, date);
            //            jssSubsystem.deleteCACert(nickname, date);
        }

        sendResponse(SUCCESS, null, null, resp);
    }

    private void validateSubjectName(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {

        CMSEngine engine = getCMSEngine();
        Enumeration<String> enum1 = req.getParameterNames();

        while (enum1.hasMoreElements()) {
            String key = enum1.nextElement();
            String value = req.getParameter(key);

            if (key.equals(Constants.PR_SUBJECT_NAME)) {
                JssSubsystem jssSubsystem = engine.getJSSSubsystem();
                jssSubsystem.isX500DN(value);
            }
        }

        sendResponse(SUCCESS, null, null, resp);
    }

    private void validateKeyLength(HttpServletResponse resp) throws IOException {
        sendResponse(SUCCESS, null, null, resp);
    }

    private void validateCurveName(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {
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

    private void validateCertExtension(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {
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

        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        jssSubsystem.checkCertificateExt(certExt);
        sendResponse(SUCCESS, null, null, resp);
    }

    private void getSubjectName(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {
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

        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        String subjectName = jssSubsystem.getSubjectDN(nickname);

        params.put(Constants.PR_SUBJECT_NAME, subjectName);
        sendResponse(SUCCESS, null, params, resp);
    }

    private void processSubjectName(HttpServletRequest req, HttpServletResponse resp)
            throws IOException, EBaseException {
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

        CMSEngine engine = getCMSEngine();
        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        String subjectName = jssSubsystem.getSubjectDN(nickname);

        params.put(Constants.PR_SUBJECT_NAME, subjectName);
        sendResponse(SUCCESS, null, params, resp);
    }

    public void setRootCertTrust(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditSubjectID = auditSubjectID();
        String nickname = req.getParameter(Constants.PR_NICK_NAME);
        String serialno = req.getParameter(Constants.PR_SERIAL_NUMBER);
        String issuername = req.getParameter(Constants.PR_ISSUER_NAME);
        String trust = req.getParameter("trustbit");

        logger.debug("CMSAdminServlet: setRootCertTrust()");

        JssSubsystem jssSubsystem = engine.getJSSSubsystem();
        try {
            jssSubsystem.setRootCertTrust(nickname, serialno, issuername, trust);
        } catch (EBaseException e) {

            auditor.log(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw e;
        }

        auditor.log(new ConfigTrustedPublicKeyEvent(
                    auditSubjectID,
                    ILogger.SUCCESS,
                    auditParams(req)));

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
    private void trustCACert(HttpServletRequest req, HttpServletResponse resp) throws IOException, EBaseException {

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditSubjectID = auditSubjectID();

        logger.debug("CMSAdminServlet: trustCACert()");

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            Enumeration<String> enum1 = req.getParameterNames();
            JssSubsystem jssSubsystem = engine.getJSSSubsystem();
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

                    jssSubsystem.trustCert(nickname, date, trust);
                }
            }

            auditor.log(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.SUCCESS,
                        auditParams(req)));

            //sendResponse(SUCCESS, null, null, resp);
            sendResponse(RESTART, null, null, resp);
        } catch (EBaseException eAudit1) {

            auditor.log(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (IOException eAudit2) {

            auditor.log(new ConfigTrustedPublicKeyEvent(
                        auditSubjectID,
                        ILogger.FAILURE,
                        auditParams(req)));

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
            //     auditor.log( auditMessage );
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
    private synchronized void runSelfTestsOnDemand(HttpServletRequest req, HttpServletResponse resp)
            throws ESelfTestException, IOException {

        CMSEngine engine = getCMSEngine();
        Auditor auditor = engine.getAuditor();

        String auditMessage = null;
        String auditSubjectID = auditSubjectID();

        // ensure that any low-level exceptions are reported
        // to the signed audit log and stored as failures
        try {
            logger.debug("CMSAdminServlet: runSelfTestsOnDemand()");

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

            SelfTestSubsystem mSelfTestSubsystem = (SelfTestSubsystem) engine.getSubsystem(SelfTestSubsystem.ID);

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
                            AuditEvent.SELFTESTS_EXECUTION,
                            auditSubjectID,
                            ILogger.FAILURE);

                auditor.log(auditMessage);

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
                        instanceFullName = SelfTestSubsystem.ID
                                + "."
                                + SelfTestSubsystem.PROP_CONTAINER
                                + "."
                                + SelfTestSubsystem.PROP_INSTANCE
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
                                    AuditEvent.SELFTESTS_EXECUTION,
                                    auditSubjectID,
                                    ILogger.FAILURE);

                        auditor.log(auditMessage);

                        // notify console of FAILURE
                        content += logMessage
                                + "\n";
                        sendResponse(ERROR, content, null, resp);

                        // raise an exception
                        throw new EMissingSelfTestException();
                    }

                    SelfTest test = mSelfTestSubsystem.getSelfTest(instanceName);

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
                                    AuditEvent.SELFTESTS_EXECUTION,
                                    auditSubjectID,
                                    ILogger.FAILURE);

                        auditor.log(auditMessage);

                        // notify console of FAILURE
                        content += logMessage
                                + "\n";
                        sendResponse(ERROR, content, null, resp);

                        // raise an exception
                        throw new EMissingSelfTestException(instanceFullName);
                    }

                    try {
                        logger.debug("CMSAdminServlet: runSelfTestsOnDemand(): running \""
                                    + test.getSelfTestName()
                                    + "\"");

                        // store this information for console notification
                        content += "CMSAdminServlet: runSelfTestsOnDemand(): running \""
                                + test.getSelfTestName()
                                + "\" . . .\n";

                        test.runSelfTest(mSelfTestSubsystem.getSelfTestLogger());

                        // store this information for console notification
                        content += "COMPLETED SUCCESSFULLY\n";

                    } catch (Exception e) {

                        logger.error("CMSAdminServlet: Selftest failure: " + e.getMessage(), e);

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
                                        AuditEvent.SELFTESTS_EXECUTION,
                                        auditSubjectID,
                                        ILogger.FAILURE);

                            auditor.log(auditMessage);

                            // notify console of FAILURE
                            content += "FAILED WITH CRITICAL ERROR\n";
                            content += logMessage
                                    + "\n";
                            sendResponse(ERROR, content, null, resp);

                            logger.error("CMSAdminServlet: Disabling subsystem due to selftest failure: " + e.getMessage());

                            engine.disableSubsystem();

                            throw new ESelfTestException("Selftest failure: " + e.getMessage(), e);

                        }
                        // store this information for console notification
                        content += "FAILED WITH NON-CRITICAL ERROR\n";
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
                        AuditEvent.SELFTESTS_EXECUTION,
                        auditSubjectID,
                        ILogger.SUCCESS);

            auditor.log(auditMessage);

            // notify console of SUCCESS
            results.put(Constants.PR_RUN_SELFTESTS_ON_DEMAND_CLASS,
                    CMSAdminServlet.class.getName());
            results.put(Constants.PR_RUN_SELFTESTS_ON_DEMAND_CONTENT,
                    content);
            sendResponse(SUCCESS, null, results, resp);

        } catch (EMissingSelfTestException eAudit1) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.SELFTESTS_EXECUTION,
                        auditSubjectID,
                        ILogger.FAILURE);

            auditor.log(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit1;
        } catch (ESelfTestException eAudit2) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.SELFTESTS_EXECUTION,
                        auditSubjectID,
                        ILogger.FAILURE);

            auditor.log(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit2;
        } catch (IOException eAudit3) {
            // store a message in the signed audit log file
            auditMessage = CMS.getLogMessage(
                        AuditEvent.SELFTESTS_EXECUTION,
                        auditSubjectID,
                        ILogger.FAILURE);

            auditor.log(auditMessage);

            // rethrow the specific exception to be handled later
            throw eAudit3;
        }
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

        if (object == null) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }

        byte rawData[] = null;

        rawData = object.getPublic().getEncoded();

        String key = null;

        // convert "rawData" into "base64Data"
        if (rawData != null) {
            String base64Data = null;

            base64Data = Utils.base64encode(rawData, true).trim();

            // concatenate lines
            key = base64Data.replace("\r", "").replace("\n", "");
        }

        if (key == null) {
            return ILogger.SIGNED_AUDIT_EMPTY_VALUE;
        }
        key = key.trim();

        return key.equals("") ? ILogger.SIGNED_AUDIT_EMPTY_VALUE : key;
    }
}
