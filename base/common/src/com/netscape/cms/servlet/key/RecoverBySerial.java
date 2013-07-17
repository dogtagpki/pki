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
package com.netscape.cms.servlet.key;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Vector;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.authentication.IAuthToken;
import com.netscape.certsrv.authorization.AuthzToken;
import com.netscape.certsrv.authorization.EAuthzAccessDenied;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.base.IArgBlock;
import com.netscape.certsrv.base.SessionContext;
import com.netscape.certsrv.common.ICMSRequest;
import com.netscape.certsrv.kra.IKeyRecoveryAuthority;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.security.Credential;
import com.netscape.cms.servlet.base.CMSServlet;
import com.netscape.cms.servlet.common.CMSRequest;
import com.netscape.cms.servlet.common.CMSTemplate;
import com.netscape.cms.servlet.common.CMSTemplateParams;
import com.netscape.cms.servlet.common.ECMSGWException;
import com.netscape.cmsutil.util.Cert;

/**
 * A class representing a recoverBySerial servlet.
 *
 * @version $Revision$, $Date$
 */
public class RecoverBySerial extends CMSServlet {

    /**
     *
     */
    private static final long serialVersionUID = -4544485601409309840L;
    private final static String INFO = "recoverBySerial";
    private final static String TPL_FILE = "recoverBySerial.template";

    private final static String IN_SERIALNO = "serialNumber";
    private final static String IN_UID = "uid";
    private final static String IN_PWD = "pwd";
    private final static String IN_PASSWORD = "p12Password";
    private final static String IN_PASSWORD_AGAIN = "p12PasswordAgain";
    private final static String IN_DELIVERY = "p12Delivery";
    private final static String IN_CERT = "cert";
    private final static String IN_NICKNAME = "nickname";

    private final static String OUT_OP = "op";
    private final static String OUT_SERIALNO = IN_SERIALNO;
    private final static String OUT_SERIALNO_IN_HEX = "serialNumberInHex";
    private final static String OUT_SERVICE_URL = "serviceURL";
    private final static String OUT_ERROR = "errorDetails";

    private final static String SCHEME = "scheme";
    private final static String HOST = "host";
    private final static String PORT = "port";

    private com.netscape.certsrv.kra.IKeyService mService = null;
    private String mFormPath = null;

    /**
     * Constructs EA servlet.
     */
    public RecoverBySerial() {
        super();
    }

    /**
     * Initializes the servlet.
     */
    public void init(ServletConfig sc) throws ServletException {
        super.init(sc);
        mFormPath = "/" + mAuthority.getId() + "/" + TPL_FILE;
        mService = (com.netscape.certsrv.kra.IKeyService) mAuthority;

        mTemplates.remove(ICMSRequest.SUCCESS);
        if (mOutputTemplatePath != null)
            mFormPath = mOutputTemplatePath;
    }

    /**
     * Returns serlvet information.
     */
    public String getServletInfo() {
        return INFO;
    }

    /**
     * Serves HTTP request. The format of this request is as follows:
     * recoverBySerial?
     * [serialNumber=<number>]
     * [uid#=<uid>]
     * [pwd#=<password>]
     * [localAgents=yes|null]
     * [recoveryID=recoveryID]
     * [pkcs12Password=<password of pkcs12>]
     * [pkcs12PasswordAgain=<password of pkcs12>]
     * [pkcs12Delivery=<delivery mechanism for pkcs12>]
     * [cert=<encryption certificate>]
     */
    public void process(CMSRequest cmsReq) throws EBaseException {

        HttpServletRequest req = cmsReq.getHttpReq();
        HttpServletResponse resp = cmsReq.getHttpResp();

        IAuthToken authToken = authenticate(cmsReq);
        AuthzToken authzToken = null;

        try {
            authzToken = authorize(mAclMethod, authToken,
                        mAuthzResourceName, "recover");
        } catch (EAuthzAccessDenied e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        } catch (Exception e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("ADMIN_SRVLT_AUTH_FAILURE", e.toString()));
        }

        if (authzToken == null) {
            cmsReq.setStatus(ICMSRequest.UNAUTHORIZED);
            return;
        }

        CMSTemplate form = null;
        Locale[] locale = new Locale[1];

        try {
            form = getTemplate(mFormPath, req, locale);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_GET_TEMPLATE", mFormPath, e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        cmsReq.setStatus(ICMSRequest.SUCCESS);
        IArgBlock header = CMS.createArgBlock();
        IArgBlock fixed = CMS.createArgBlock();
        CMSTemplateParams argSet = new CMSTemplateParams(header, fixed);

        // set host name and port.
        HttpServletRequest httpReq = cmsReq.getHttpReq();
        String host = httpReq.getServerName();
        int port = httpReq.getServerPort();
        String scheme = httpReq.getScheme();

        fixed.set(HOST, host);
        fixed.set(PORT, Integer.valueOf(port));
        fixed.set(SCHEME, scheme);

        SessionContext ctx = null;

        try {
            String initAsyncRecovery = req.getParameter("initAsyncRecovery");

            // this information is needed within the server for
            // various signed audit log messages to report
            ctx = SessionContext.getContext();

            /*
               When Recovery is first initiated, if it is in asynch mode,
               no pkcs#12 password is needed.
               The initiating agent uid will be recorded in the recovery
               request.
               Later, as approving agents submit their approvals, they will
               also be listed in the request.
             */
            if ((initAsyncRecovery != null) &&
                    initAsyncRecovery.equalsIgnoreCase("ON")) {
                process(form, argSet, header,
                        req.getParameter(IN_SERIALNO),
                        req.getParameter(IN_CERT),
                        req, resp, locale[0]);

                int requiredNumber = mService.getNoOfRequiredAgents();
                header.addIntegerValue("noOfRequiredAgents", requiredNumber);
            } else {
                String recoveryID = req.getParameter("recoveryID");

                if (recoveryID != null && !recoveryID.equals("")) {
                    ctx.put(SessionContext.RECOVERY_ID,
                            req.getParameter("recoveryID"));
                }
                byte pkcs12[] = process(form, argSet, header,
                        req.getParameter(IN_SERIALNO),
                        req.getParameter("localAgents"),
                        req.getParameter(IN_PASSWORD),
                        req.getParameter(IN_PASSWORD_AGAIN),
                        req.getParameter(IN_CERT),
                        req.getParameter(IN_DELIVERY),
                        req.getParameter(IN_NICKNAME),
                        req, resp, locale[0]);

                if (pkcs12 != null) {
                    //resp.setStatus(HttpServletResponse.SC_OK);
                    resp.setContentType("application/x-pkcs12");
                    //resp.setContentLength(pkcs12.length);
                    resp.getOutputStream().write(pkcs12);
                    mRenderResult = false;
                    return;
                }
            }
        } catch (NumberFormatException e) {
            header.addStringValue(OUT_ERROR,
                    CMS.getUserMessage(locale[0], "CMS_BASE_INTERNAL_ERROR", e.toString()));
        } catch (IOException e) {
            header.addStringValue(OUT_ERROR,
                    CMS.getUserMessage(locale[0], "CMS_BASE_INTERNAL_ERROR", e.toString()));
        } finally {
            SessionContext.releaseContext();
        }

        // return status page
        try {
            ServletOutputStream out = resp.getOutputStream();

            resp.setContentType("text/html");
            form.renderOutput(out, argSet);
        } catch (IOException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSGW_ERR_STREAM_TEMPLATE", e.toString()));
            throw new ECMSGWException(
                    CMS.getUserMessage("CMS_GW_DISPLAY_TEMPLATE_ERROR"));
        }

        cmsReq.setStatus(ICMSRequest.SUCCESS);
    }

    /**
     * Async Key Recovery - request initiation
     */
    private void process(CMSTemplate form, CMSTemplateParams argSet,
            IArgBlock header, String seq, String cert,
            HttpServletRequest req, HttpServletResponse resp,
            Locale locale) {

        // seq is the key id
        if (seq == null) {
            header.addStringValue(OUT_ERROR, "sequence number not found");
            return;
        }
        X509CertImpl x509cert = null;

        if (cert == null || cert.trim().length() == 0) {
            header.addStringValue(OUT_ERROR, "certificate not found");
            return;
        } else {
            try {
                x509cert = Cert.mapCert(cert);
            } catch (IOException e) {
                header.addStringValue(OUT_ERROR, e.toString());
            }
        }
        if (x509cert == null) {
            header.addStringValue(OUT_ERROR, "invalid X.509 certificate");
            return;
        }

        SessionContext sContext = SessionContext.getContext();

        try {
            String reqID = mService.initAsyncKeyRecovery(
                    new BigInteger(seq), x509cert,
                      (String) sContext.get(SessionContext.USER_ID));
            header.addStringValue(OUT_SERIALNO, req.getParameter(IN_SERIALNO));
            header.addStringValue(OUT_SERIALNO_IN_HEX,
                    new BigInteger(req.getParameter(IN_SERIALNO)).toString(16));
            header.addStringValue("requestID", reqID);
        } catch (EBaseException e) {
            String error =
                    "Failed to recover key for key id " +
                            seq + ".\nException: " + e.toString();

            CMS.getLogger().log(ILogger.EV_SYSTEM,
                    ILogger.S_KRA, ILogger.LL_FAILURE, error);
            try {
                ((IKeyRecoveryAuthority) mService).createError(seq, error);
            } catch (EBaseException eb) {
                CMS.getLogger().log(ILogger.EV_SYSTEM,
                        ILogger.S_KRA, ILogger.LL_FAILURE, eb.toString());
            }
        }
        return;
    }

    /**
     * Recovers a key. The p12 will be protected by the password
     * provided by the administrator.
     */
    private byte[] process(CMSTemplate form, CMSTemplateParams argSet,
            IArgBlock header, String seq, String localAgents,
            String password, String passwordAgain,
            String cert, String delivery, String nickname,
            HttpServletRequest req, HttpServletResponse resp,
            Locale locale) {
        if (seq == null) {
            header.addStringValue(OUT_ERROR, "sequence number not found");
            return null;
        }
        if (password == null || password.equals("")) {
            header.addStringValue(OUT_ERROR, "PKCS12 password not found");
            return null;
        }
        if (passwordAgain == null || !passwordAgain.equals(password)) {
            header.addStringValue(OUT_ERROR, "PKCS12 password not matched");
            return null;
        }
        X509CertImpl x509cert = null;

        if (cert == null || cert.trim().length() == 0) {
            // perform recovery
            header.addStringValue(OUT_ERROR, "certificate not found");
            return null;
        } else {
            try {
                x509cert = Cert.mapCert(cert);
            } catch (IOException e) {
                header.addStringValue(OUT_ERROR, e.toString());
            }
        }
        if (x509cert == null) {
            header.addStringValue(OUT_ERROR, "invalid X.509 certificate");
            return null;
        }
        try {
            Credential creds[] = null;

            SessionContext sContext = SessionContext.getContext();
            String agent = null;

            if (sContext != null) {
                agent = (String) sContext.get(SessionContext.USER_ID);
            }
            if (CMS.getConfigStore().getBoolean("kra.keySplitting")) {
                if (localAgents == null) {
                    String recoveryID = req.getParameter("recoveryID");

                    if (recoveryID == null || recoveryID.equals("")) {
                        header.addStringValue(OUT_ERROR, "No recovery ID specified");
                        return null;
                    }
                    Hashtable<String, Object> params = mService.createRecoveryParams(recoveryID);

                    params.put("keyID", req.getParameter(IN_SERIALNO));

                    header.addStringValue("recoveryID", recoveryID);

                    params.put("agent", agent);

                    // new thread to wait for pk12
                    Thread waitThread = new WaitApprovalThread(recoveryID,
                            seq, password, x509cert, delivery, nickname,
                            SessionContext.getContext());

                    waitThread.start();
                    return null;
                } else {
                    Vector<Credential> v = new Vector<Credential>();

                    for (int i = 0; i < mService.getNoOfRequiredAgents(); i++) {
                        String uid = req.getParameter(IN_UID + i);
                        String pwd = req.getParameter(IN_PWD + i);

                        if (uid != null && pwd != null && !uid.equals("") &&
                                !pwd.equals("")) {
                            v.addElement(new Credential(uid, pwd));
                        } else {
                            header.addStringValue(OUT_ERROR, "Uid(s) or password(s) are not provided");
                            return null;
                        }
                    }
                    if (v.size() != mService.getNoOfRequiredAgents()) {
                        header.addStringValue(OUT_ERROR, "Uid(s) or password(s) are not provided");
                        return null;
                    }
                    creds = new Credential[v.size()];
                    v.copyInto(creds);
                }

                header.addStringValue(OUT_OP,
                        req.getParameter(OUT_OP));
                header.addBigIntegerValue(OUT_SERIALNO,
                        new BigInteger(seq), 10);
                header.addBigIntegerValue(OUT_SERIALNO_IN_HEX,
                        new BigInteger(seq), 16);
                header.addStringValue(OUT_SERVICE_URL,
                        req.getRequestURI());
                byte pkcs12[] = mService.doKeyRecovery(
                        new BigInteger(seq),
                        creds, password, x509cert,
                        delivery, nickname, agent);

                return pkcs12;
            } else {
                String recoveryID = req.getParameter("recoveryID");

                if (recoveryID == null || recoveryID.equals("")) {
                    header.addStringValue(OUT_ERROR, "No recovery ID specified");
                    return null;
                }
                Hashtable<String, Object> params = mService.createRecoveryParams(recoveryID);

                params.put("keyID", req.getParameter(IN_SERIALNO));

                header.addStringValue("recoveryID", recoveryID);

                params.put("agent", agent);

                // new thread to wait for pk12
                Thread waitThread = new WaitApprovalThread(recoveryID,
                        seq, password, x509cert, delivery, nickname,
                        SessionContext.getContext());

                waitThread.start();
                return null;
            }
        } catch (EBaseException e) {
            header.addStringValue(OUT_ERROR, e.toString(locale));
        } catch (Exception e) {
            header.addStringValue(OUT_ERROR, e.toString());
        }
        return null;
    }

    /**
     * Wait approval thread. Wait for recovery agents' approval
     * exit when required number of approval received
     */
    final class WaitApprovalThread extends Thread {
        String theRecoveryID = null;
        String theSeq = null;
        String thePassword = null;
        X509CertImpl theCert = null;
        String theDelivery = null;
        String theNickname = null;
        SessionContext theSc = null;

        /**
         * Wait approval thread constructor including thread name
         */
        public WaitApprovalThread(String recoveryID, String seq,
                String password, X509CertImpl cert,
                String delivery, String nickname, SessionContext sc) {
            super();
            super.setName("waitApproval." + recoveryID + "-" +
                    (Thread.activeCount() + 1));
            theRecoveryID = recoveryID;
            theSeq = seq;
            thePassword = password;
            theCert = cert;
            theDelivery = delivery;
            theNickname = nickname;
            theSc = sc;
        }

        public void run() {
            SessionContext.setContext(theSc);
            Credential creds[] = null;

            try {
                creds = mService.getDistributedCredentials(theRecoveryID);
            } catch (EBaseException e) {
                String error =
                        "Failed to get required approvals for recovery id " +
                                theRecoveryID + ".\nException: " + e.toString();

                CMS.getLogger().log(ILogger.EV_SYSTEM,
                        ILogger.S_KRA, ILogger.LL_FAILURE, error);
                try {
                    ((IKeyRecoveryAuthority) mService).createError(theRecoveryID, error);
                } catch (EBaseException eb) {
                    CMS.getLogger().log(ILogger.EV_SYSTEM,
                            ILogger.S_KRA, ILogger.LL_FAILURE, eb.toString());
                }
                return;
            }

            SessionContext sContext = SessionContext.getContext();

            try {
                byte pkcs12[] = mService.doKeyRecovery(
                        new BigInteger(theSeq),
                        creds, thePassword, theCert,
                        theDelivery, theNickname,
                        (String) sContext.get(SessionContext.USER_ID));

                ((IKeyRecoveryAuthority) mService).createPk12(theRecoveryID, pkcs12);
            } catch (EBaseException e) {
                String error =
                        "Failed to recover key for recovery id " +
                                theRecoveryID + ".\nException: " + e.toString();

                CMS.getLogger().log(ILogger.EV_SYSTEM,
                        ILogger.S_KRA, ILogger.LL_FAILURE, error);
                try {
                    ((IKeyRecoveryAuthority) mService).createError(theRecoveryID, error);
                } catch (EBaseException eb) {
                    CMS.getLogger().log(ILogger.EV_SYSTEM,
                            ILogger.S_KRA, ILogger.LL_FAILURE, eb.toString());
                }
            }
            return;
        }
    }

}
