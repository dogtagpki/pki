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
package com.netscape.admin.certsrv.keycert;

import java.awt.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.console.*;

/**
 * WizardInfo for certificate setup wizard
 * Once complete, we need to zap this object.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.keycert
 */
public class CertSetupWizardInfo extends WizardInfo {

    private AdminConnection mConnection;
    private ConsoleInfo mConsoleInfo;
    public static final String FRAME = "frame";
    public static final String SERVERINFO = "serverInfo";
    public static final String TOKENNAME = "tokenName";
    public static final String DBPASSWD = "dbPasswd";
    public static final String OPTYPE = "operationType";
    public static final String INSTALLTYPE = "install";
    public static final String REQUESTTYPE = "request";
//    public static final String CA_SIGNING_CERT = "caSigningCert";
 //   public static final String RA_SIGNING_CERT = " raSigningCert";
 //   public static final String KRA_TRANSPORT_CERT = "kraTransportCert";
 //   public static final String SSL_SERVER_CERT = "sslServerCert";
    public static final String SERVER_CERT_CHAIN = "serverCertChain";
    public static final String TRUSTED_CA_CERT = "trustedCACert";
    public static final String TRUSTED_CERT = "trustedCert";
//    public static final String SERVER_CERT = "serverCert";
    public static final String SELF_SIGNED = "selfSigned";
    public static final String SUBORDINATE_CA = "subordinateCA";
    public static final String CA_EMAIL = "caEmail";
    public static final String CA_URL = "caUrl";
    public static final String MANUAL = "manual";
    public static final String SUBMIT_METHOD = "reqSubmitMethod";
    public static final String KEY_MATERIAL = "keyMaterial";
    public static final String CA_TYPE = "caType";
    public static final String DERVALUE = "derValue";
    public static final String INSTALLCERTTYPE = "installCertType";
    public static final String ALL_INFO = "allInfo";
    public static final String BEGIN_YEAR = "beginYear";
    public static final String BEGIN_MONTH = "beginMonth";
    public static final String BEGIN_DATE = "beginDate";
    public static final String BEGIN_HOUR = "beginHour";
    public static final String BEGIN_MIN = "beginMin";
    public static final String BEGIN_SEC = "beginSec";
    public static final String AFTER_YEAR = "afterYear";
    public static final String AFTER_MONTH = "afterMonth";
    public static final String AFTER_DATE = "afterDate";
    public static final String AFTER_HOUR = "afterHour";
    public static final String AFTER_MIN = "afterMin";
    public static final String AFTER_SEC = "afterSec";
    public static final String NICKNAME = "nickname";
    public static final String CERT_CONTENT = "certContent";

    public CertSetupWizardInfo(AdminConnection conn, ConsoleInfo info) {
        super();
        mConnection = conn;
		mConsoleInfo = info;
    }

    public JFrame getFrame() {
        return (JFrame)get(FRAME);
    }

    public CMSServerInfo getServerInfo() {
        return (CMSServerInfo)get(SERVERINFO);
    }

    public AdminConnection getAdminConnection() {
        return mConnection;
    }

    public ConsoleInfo getAdminConsoleInfo() {
        return mConsoleInfo;
    }

    // if mode = 0, then it is in root cert mode.
    // if mode = 1, then it is in user cert mode.
    public void setMode(String mode) {
        put("mode", mode);
    }

    public String getMode() {
        return (String)get("mode");
    }

    public String getCertType() {
        return (String)get(Constants.PR_CERTIFICATE_TYPE);
    }

    public void setCertType(String certType) {
        put(Constants.PR_CERTIFICATE_TYPE, certType);
    }

    public String getSubmitMethod() {
        return (String)get(SUBMIT_METHOD);
    }

    public String getCAType() {
        return (String)get(CA_TYPE);
    }

    public boolean isNewKey() {
        String isNew = (String)get(KEY_MATERIAL);
        if (isNew != null && isNew.equals(Constants.TRUE))
            return true;
        return false;
    }

    public String getOperationType() {
        String opType = (String)get(OPTYPE);
        return opType;
    }

    public boolean isSSLCertLocalCA() {
        String val = (String)get(ConfigConstants.PR_SSLCERT_LOCALCA);
        if (val == null)
            return false;
        else if (val.equals(Constants.TRUE))
            return true;
        return false;
    }

    // set true or false
    public void setSSLCertLocalCA(String val) {
        put(ConfigConstants.PR_SSLCERT_LOCALCA, val);
    }

    public byte[] getDERValue() {
        byte[] derValue = (byte[])get(DERVALUE);
        return derValue;
    }

    public String getTokenName() {
        return (String)get(TOKENNAME);
    }

    public String getKeyLength() {
        return (String)get(Constants.PR_KEY_LENGTH);
    }

    public String getKeyCurveName() {
        return (String)get(Constants.PR_KEY_CURVENAME);
    }

    public String getKeyType() {
        return (String)get(Constants.PR_KEY_TYPE);
    }

    public String getSubjectName() {
        return (String)get(Constants.PR_SUBJECT_NAME);
    }

    public void setSubjectName(String str) {
        put(Constants.PR_SUBJECT_NAME, str);
    }

    public String getCSR() {
        return (String)get(Constants.PR_CSR);
    }

    public String getPKCS10() {
        String val = (String)get(Constants.PR_PKCS10);
        if (val != null && !val.equals(""))
            return val;
        return null;
    }

    public void setPKCS10(String b64E) {
        put(Constants.PR_PKCS10, b64E);
    }

    public String getCertFilePath() {
        String val = (String)get(Constants.PR_CERT_FILEPATH);
        if (val != null && !val.equals(""))
            return val;
        return null;
    }

    public void setCertFilePath(String path) {
        put(Constants.PR_CERT_FILEPATH, path);
    }

    public String getCertSubjectName() {
        return (String)get(Constants.PR_CERT_SUBJECT_NAME);
    }

    public String getIssuerName() {
        return (String)get(Constants.PR_ISSUER_NAME);
    }

    public String getSerialNumber() {
        return (String)get(Constants.PR_SERIAL_NUMBER);
    }

    public String getNotBefore() {
        return (String)get(Constants.PR_BEFORE_VALIDDATE);
    }

    public String getNotAfter() {
        return (String)get(Constants.PR_AFTER_VALIDDATE);
    }

    public String getInstallCertType() {
        return (String)get(INSTALLCERTTYPE);
    }

    public String getValidityPeriod() {
        return (String)get(Constants.PR_VALIDITY_PERIOD);
    }

    public String getTokenList() {
        return (String)get(Constants.PR_TOKEN_LIST);
    }

    public Boolean isCertAdded() {
        return (Boolean)get(Constants.PR_ADD_CERT);
    }

    public NameValuePairs getNameValuePairs() {
        return (NameValuePairs)get(ALL_INFO);
    }

    public String getBeginYear() {
        return (String)get(Constants.PR_BEGIN_YEAR);
    }

    public String getBeginMonth() {
        return (String)get(Constants.PR_BEGIN_MONTH);
    }

    public String getBeginDate() {
        return (String)get(Constants.PR_BEGIN_DATE);
    }

    public String getBeginHour() {
        return (String)get(Constants.PR_BEGIN_HOUR);
    }

    public String getBeginMin() {
        return (String)get(Constants.PR_BEGIN_MIN);
    }

    public String getBeginSec() {
        return (String)get(Constants.PR_BEGIN_SEC);
    }

    public String getAfterYear() {
        return (String)get(Constants.PR_AFTER_YEAR);
    }

    public String getAfterMonth() {
        return (String)get(Constants.PR_AFTER_MONTH);
    }

    public String getAfterDate() {
        return (String)get(Constants.PR_AFTER_DATE);
    }

    public String getAfterHour() {
        return (String)get(Constants.PR_AFTER_HOUR);
    }

    public String getAfterMin() {
        return (String)get(Constants.PR_AFTER_MIN);
    }

    public String getAfterSec() {
        return (String)get(Constants.PR_AFTER_SEC);
    }

    public String getNickname() {
        return (String)get(Constants.PR_NICKNAME);
    }

    public String getCertContent() {
        return (String)get(Constants.PR_CERT_CONTENT);
    }

    public String getHashType() {
        return (String)get(ConfigConstants.PR_HASH_TYPE);
    }

    public void setHashType(String type) {
        put(ConfigConstants.PR_HASH_TYPE, type);
    }

    public String getSignedByType() {
        return (String)get(ConfigConstants.PR_SIGNEDBY_TYPE);
    }

    public void setSignedByType(String type) {
        put(ConfigConstants.PR_SIGNEDBY_TYPE, type);
    }


    public boolean isLoggedIn() {
        String value = (String)get(Constants.PR_LOGGED_IN);
        if (value != null && value.equals(Constants.FALSE))
            return false;
        return true;
    }

    public String getCertRequestDir() {
        return (String)get(Constants.PR_CERT_REQUEST_DIR);
    }

    public void setCMHost(String host) {
        put(ConfigConstants.CA_HOST, host);
    }

    public String getCMHost() {
        return (String)get(ConfigConstants.CA_HOST);
    }

    public void setCMEEPort(String port) {
        put(ConfigConstants.CA_EEPORT, port);
    }

    public String getCMEEPort() {
        return (String)get(ConfigConstants.CA_EEPORT);
    }

    public void setCMEEType(String type) {
        put(ConfigConstants.CA_EETYPE, type);
    }

    public String getCMEEType() {
        return (String)get(ConfigConstants.CA_EETYPE);
    }

    public void setRequestStatus(String requestStatus) {
        put(getCertType()+ConfigConstants.PR_CERT_REQUEST+"Status", requestStatus);
    }

    public String getRequestStatus() {
        return (String)get(getCertType()+ConfigConstants.PR_CERT_REQUEST+"Status");
    }

    public void setRequestID(String requestID) {
        put(getCertType()+ConfigConstants.PR_CERT_REQUEST, requestID);
    }

    public String getRequestID() {
        return (String)get(getCertType()+ConfigConstants.PR_CERT_REQUEST);
    }

    public void setRequestSent(boolean sent) {
        if (sent)
            put(getCertType()+"Sent", ConfigConstants.TRUE);
        else
            put(getCertType()+"Sent", ConfigConstants.FALSE);
    }

    public boolean requestSent() {
        String str = (String)get(getCertType()+"Sent");
        if (str == null || str.equals(ConfigConstants.FALSE))
            return false;
        return true;
    }

    public void setRequestError(String error) {
        put(getCertType()+"Error", error);
    }

    public String getRequestError() {
        return (String)get(getCertType()+"Error");
    }

    public void setCertSubType(String str) {
        put(Constants.PR_CERTIFICATE_SUBTYPE, str);
    }

    public String getCertSubType() {
        return (String)get(Constants.PR_CERTIFICATE_SUBTYPE);
    }

    public void setNicknames(String str) {
        put(Constants.PR_ALL_NICKNAMES, str);
    }

    public String getNicknames() {
        return (String)get(Constants.PR_ALL_NICKNAMES);
    }
}

