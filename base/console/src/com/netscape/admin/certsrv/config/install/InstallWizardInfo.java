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
package com.netscape.admin.certsrv.config.install;

import java.awt.*;
import javax.swing.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.console.*;

/**
 * WizardInfo for certificate setup wizard
 * Once complete, we need to zap this object.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
public class InstallWizardInfo extends WizardInfo {
    private static final int DB_PORT = 38900;
    private static final String BINDDN = "cn=Directory Manager";
    public static final String ALL_CERT_INFO = "allInfo";
    private static final String CA_KEY_TYPE = "caKeyType";
    private static final String CA_KEY_LEN = "caKeyLen";
    private static final String OCSP_TOKEN_NAME = "ocspTokenName";
    private static final String OCSP_TOKEN_PASSWD = "ocspTokenPwd";
    private static final String CA_TOKEN_NAME = "caTokenName";
    private static final String CA_TOKEN_PASSWD = "caTokenPwd";
    private static final String RA_TOKEN_NAME = "raTokenName";
    private static final String RA_TOKEN_PASSWD = "raTokenPwd";
    private static final String KRA_TOKEN_NAME = "kraTokenName";
    private static final String KRA_TOKEN_PASSWD = "kraTokenPwd";
    private static final String SSL_TOKEN_NAME = "sslTokenName";
    private static final String SSL_TOKEN_PASSWD = "sslTokenPwd";
    private static final String MIGRATE_CA_TOKEN_NAME = "migrateCATokenName";
    private static final String MIGRATE_SSL_TOKEN_NAME = "migrateSSLTokenName";
    private static final String INSTALLCERT_NOW = "installCertNow";
    private static final String CLONING = "cloning";
    private static final String CACLONING = "cacloning";
    private static final String RACLONING = "racloning";
    private static final String KRACLONING = "kracloning";
    private static final String SSLCLONING = "sslcloning";

    private static final String CA_CLONING_CERT = "caSigningCert";
    private static final String RA_CLONING_CERT = "raSigningCert";
    private static final String KRA_CLONING_CERT = "kraTransportCert";
    private static final String OCSP_CLONING_CERT = "ocspSigningCert";

	private String mPassword = null;

    private ConsoleInfo mConsoleInfo;

    public InstallWizardInfo() {
        super();
    }

    public InstallWizardInfo(ConsoleInfo consoleInfo) {
        super();
        mConsoleInfo = consoleInfo;
    }

    public JFrame getAdminFrame() {
        return (JFrame)get("adminFrame");
    }

    public boolean doKeySplitting() {
        String str = (String)get("kra.keySplitting");
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        else
            return false;

    }

    public void setAdminFrame(JFrame frame) {
        put("adminFrame", frame);
    }

    public ConsoleInfo getAdminConsoleInfo() {
        return mConsoleInfo;
    }

    public String getStages() {
        return (String)get(ConfigConstants.STAGES);
    }

    public String getCloneCertsList() {
        String s = (String)get(ConfigConstants.PR_CLONE_CERTIFICATES);
        if (s == null || s.equals(""))
            return " ";
        return s;
    }

    public String getCloneSubsystem() {

        String s = (String)get("selected_sub");

        if(s == null || s.equals(""))
            return null;

        return s;

    }

    public boolean isCACloningDone() {
        String str = (String)get(ConfigConstants.STAGE_CACLONING);

        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        else
            return false;
    }

    public void setCACloningDone(String str) {
        put(ConfigConstants.STAGE_CACLONING, str);
    }

    public boolean isOCSPCloningDone() {
        String str = (String)get(ConfigConstants.STAGE_OCSPCLONING);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;

        return false;
    }

    public void setOCSPCloningDone(String str) {
        put(ConfigConstants.STAGE_OCSPCLONING, str);
    }

    public boolean isRACloningDone() {
        String str = (String)get(ConfigConstants.STAGE_RACLONING);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;

        return false;
    }

    public void setRACloningDone(String str) {
        put(ConfigConstants.STAGE_RACLONING, str);
    }

    public boolean isKRACloningDone() {
        String str = (String)get(ConfigConstants.STAGE_KRACLONING);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;

        return false;
    }

    public boolean isTKSCloningDone() {
        String str = (String)get(ConfigConstants.STAGE_TKSCLONING);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;

        return false;
    }

    public void setUpdateDBInfoDone(String str) {
        put(ConfigConstants.STAGE_UPDATE_DB_INFO, str);
    }

    public boolean isUpdateDBInfoDone() {
        String str = (String)get(ConfigConstants.STAGE_UPDATE_DB_INFO);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public void setKRACloningDone(String str) {
        put(ConfigConstants.STAGE_KRACLONING, str);
    }

    public boolean isSSLCloningDone() {
        String str = (String)get(ConfigConstants.STAGE_SSLCLONING);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public void setSSLCloningDone(String str) {
        put(ConfigConstants.STAGE_SSLCLONING, str);
    }

    public boolean isCloneCASubsystem() {
        String str = (String)get(ConfigConstants.PR_CLONE_SUBSYSTEM);
        if (str != null && str.equals(ConfigConstants.PR_CA))
            return true;
        return false;
    }

    public boolean isCloneRASubsystem() {
        String str = (String)get(ConfigConstants.PR_CLONE_SUBSYSTEM);
        if (str != null && str.equals(ConfigConstants.PR_RA))
            return true;
        return false;
    }
    public boolean isCloneKRASubsystem() {
        String str = (String)get(ConfigConstants.PR_CLONE_SUBSYSTEM);
        if (str != null && str.equals(ConfigConstants.PR_KRA))
            return true;
        return false;
    }
    public boolean isCloneOCSPSubsystem() {
        String str = (String)get(ConfigConstants.PR_CLONE_SUBSYSTEM);
        if (str != null && str.equals(ConfigConstants.PR_OCSP))
            return true;
        return false;
    }
    public boolean isCloneTKSSubsystem() {
        String str = (String)get(ConfigConstants.PR_CLONE_SUBSYSTEM);
        if (str != null && str.equals(ConfigConstants.PR_TKS))
            return true;
        return false;
    }
    public boolean isCloneMasterDone() {
        String str = (String)get(ConfigConstants.STAGE_CLONEMASTER);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public void setCloneMasterDone(String str) {
        put(ConfigConstants.STAGE_CLONEMASTER, str);
    }

    public boolean isNetworkDone() {
        String str = (String)get(ConfigConstants.STAGE_SETUP_PORTS);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isAdministratorDone() {
        String str = (String)get(ConfigConstants.STAGE_SETUP_ADMINISTRATOR);
        if (str == null || str.equals("") || str.equals(ConfigConstants.FALSE))
            return false;

        return true;
    }

    public boolean isServicesDone() {
        String str = (String)get(ConfigConstants.STAGE_SETUP_SUBSYSTEMS);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isMigrationDone() {
        String str = (String)get(ConfigConstants.STAGE_DATA_MIGRATION);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isKRANMSchemeDone() {
        String str = (String)get(ConfigConstants.STAGE_KRA_NM_SCHEME);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isCACertRequestBack() {
        String str = (String)get(ConfigConstants.CA_CERT_REQUEST_BACK);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isRACertRequestBack() {
        String str = (String)get(ConfigConstants.RA_CERT_REQUEST_BACK);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isOCSPCertRequestBack() {
        String str = (String)get(ConfigConstants.OCSP_CERT_REQUEST_BACK);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isKRACertRequestBack() {
        String str = (String)get(ConfigConstants.KRA_CERT_REQUEST_BACK);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isSSLCertRequestBack() {
        String str = (String)get(ConfigConstants.SSL_CERT_REQUEST_BACK);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isSelfSignedCACertDone() {
        String str = (String)get(ConfigConstants.STAGE_CA_SELFSIGNED_CERT);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isCACertRequestDone() {
        String str = (String)get(ConfigConstants.STAGE_CA_CERT_REQUEST);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isCACertInstalledDone() {
        String str = (String)get(ConfigConstants.STAGE_CA_CERT_INSTALL);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isCACertChainImportDone() {
        String str = (String)get(ConfigConstants.STAGE_CA_CERTCHAIN_IMPORT);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }
    public boolean isNumberPageDone(){
        String str = (String)get(ConfigConstants.PR_SERIAL_REQUEST_NUMBER);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }
    public void setNumberPageDone(String str) {
        put(ConfigConstants.PR_SERIAL_REQUEST_NUMBER, str);
    }
    public boolean isClonePageDone(){
        String str = (String)get(ConfigConstants.PR_CLONE_SETTING_DONE);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }
    public void setClonePageDone(String str) {
        put(ConfigConstants.PR_CLONE_SETTING_DONE, str);
    }
    public boolean isOCSPCertChainImportDone() {
        String str = (String)get(ConfigConstants.STAGE_OCSP_CERTCHAIN_IMPORT);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isRALocalCertDone() {
        String str = (String)get(ConfigConstants.STAGE_RA_LOCAL_CERT);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isRACertRequestDone() {
        String str = (String)get(ConfigConstants.STAGE_RA_CERT_REQUEST);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isOCSPLocalCertDone() {
        String str = (String)get(ConfigConstants.STAGE_OCSP_LOCAL_CERT);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isOCSPCertRequestDone() {
        String str = (String)get(ConfigConstants.STAGE_OCSP_CERT_REQUEST);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isOCSPCertInstalledDone() {
        String str = (String)get(ConfigConstants.STAGE_OCSP_CERT_INSTALL);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isRACertInstalledDone() {
        String str = (String)get(ConfigConstants.STAGE_RA_CERT_INSTALL);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isRACertChainImportDone() {
        String str = (String)get(ConfigConstants.STAGE_RA_CERTCHAIN_IMPORT);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isKRALocalCertDone() {
        String str = (String)get(ConfigConstants.STAGE_KRA_LOCAL_CERT);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isKRACertRequestDone() {
        String str = (String)get(ConfigConstants.STAGE_KRA_CERT_REQUEST);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isKRACertInstalledDone() {
        String str = (String)get(ConfigConstants.STAGE_KRA_CERT_INSTALL);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isKRACertChainImportDone() {
        String str = (String)get(ConfigConstants.STAGE_KRA_CERTCHAIN_IMPORT);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }
    public boolean isSSLLocalCertDone() {
        String str = (String)get(ConfigConstants.STAGE_SSL_LOCAL_CERT);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isSSLCertRequestDone() {
        String str = (String)get(ConfigConstants.STAGE_SSL_CERT_REQUEST);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isSSLCertInstalledDone() {
        String str = (String)get(ConfigConstants.STAGE_SSL_CERT_INSTALL);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isSSLCertChainImportDone() {
        String str = (String)get(ConfigConstants.STAGE_SSL_CERTCHAIN_IMPORT);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }
    public String getNextAvailPort() {
        return (String)get(ConfigConstants.PR_NEXT_AVAIL_PORT);
    }

    public void setSubsystems(String str) {
        put(ConfigConstants.PR_SUBSYSTEMS, str);
    }

    public String getSubsystems() {
        return (String)get(ConfigConstants.PR_SUBSYSTEMS);
    }

    public void setReplicationEnabled(String str) {
        put(ConfigConstants.PR_ENABLE_REPLICATION, str);
    }

    public boolean isReplicationEnabled() {
        String str = (String)get(ConfigConstants.PR_ENABLE_REPLICATION);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public void setAgreementDone(String str) {
        put(ConfigConstants.STAGE_REPLICATION_AGREEMENT, str);
    }

    public boolean isAgreementDone() {
        String str = (String)get(ConfigConstants.STAGE_REPLICATION_AGREEMENT);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        else
            return false;
    }

    public void setDBCreated(String str) {
        put(ConfigConstants.PR_IS_DBCREATED, str);
    }

    public void setCloneDBCreated(String str) {
        put(ConfigConstants.PR_IS_CLONEDDB_CREATED, str);
    }

    public boolean isDBCreated() {
        String str = (String)get(ConfigConstants.PR_IS_DBCREATED);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isCloneDBCreated() {
        String str = (String)get(ConfigConstants.PR_IS_CLONEDDB_CREATED);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public void setDBCreateNow(String str) {
        put("dbCreateNow", str);
    }

    public boolean isDBCreateNow() {
        String str = (String)get("dbCreateNow");
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

	public String getSingleSignOnPassword() {
		return mPassword;
	}

	public void setSingleSignOnPassword(String password) {
		mPassword = password;
	}

    public void setCertAdminUid(String uid) {
        put(ConfigConstants.PR_CERT_ADMINUID, uid);
    }

    public String getCertAdminUid() {
        return (String)get(ConfigConstants.PR_CERT_ADMINUID);
    }

    public void setCertAdminName(String name) {
        put(ConfigConstants.PR_CERT_ADMINNAME, name);
    }

    public String getCertAdminName() {
        return (String)get(ConfigConstants.PR_CERT_ADMINNAME);
    }

    public void setDBPort(String val) {
        put(ConfigConstants.PR_DB_PORT, val);
    }

    public int getDBPort() {
        String val = (String)get(ConfigConstants.PR_DB_PORT);
        if (val != null)
            return Integer.parseInt(val);
        return 38900;
    }

    public void setDBName(String name) {
        put(ConfigConstants.PR_DB_NAME, name);
    }

    public String getDBName() {
        String dbName = (String)get(ConfigConstants.PR_DB_NAME);
        if (dbName == null)
            dbName = "";
        return dbName;
    }

    public void setCloneDBName(String name) {
        put(ConfigConstants.PR_CLONEDDB_NAME, name);
    }

    public String getCloneDBName() {
        String dbName = (String)get(ConfigConstants.PR_CLONEDDB_NAME);
        if (dbName == null)
            dbName = "";
        return dbName;
    }

    public void setDBBindDN(String val) {
        put(ConfigConstants.PR_DB_BINDDN, val);
    }

    public String getDBBindDN() {
        String dn = (String)get(ConfigConstants.PR_DB_BINDDN);
        if (dn == null)
            dn = BINDDN;
        return dn;
    }

    public String getAdminPort() {
        String val = (String)get(ConfigConstants.PR_RADM_PORT);
        if (val == null)
            val = "8200";
        return val;
    }

    public void setAdminPort(String val) {
        put(ConfigConstants.PR_RADM_PORT, val);
    }

    public String getEEPort() {
        String val = (String)get(ConfigConstants.PR_EE_PORT);
        if (val == null || val.equals(""))
            val = "81";
        return val;
    }

    public void setEEPort(String port) {
        put(ConfigConstants.PR_EE_PORT, port);
    }

    public String getEESecurePort() {
        String val = (String)get(ConfigConstants.PR_EE_SECURE_PORT);
        if (val == null)
            val = "8001";
        return val;
    }

    public void setEESecurePort(String port) {
        put(ConfigConstants.PR_EE_SECURE_PORT, port);
    }

    public String getAgentPort() {
        String val = (String)get(ConfigConstants.PR_AGENT_PORT);
        if (val == null)
            val = "8100";
        return val;
    }

    public void setAgentPort(String val) {
        put(ConfigConstants.PR_AGENT_PORT, val);
    }

    public boolean isEEEnabled() {
        String val = (String)get(ConfigConstants.PR_EE_PORT_ENABLE);
        if (val != null && val.equals(Constants.TRUE))
            return true;
        return false;
    }

    public void setEEEnable(String enable) {
        put(ConfigConstants.PR_EE_PORT_ENABLE, enable);
    }

    public String getCertType() {
         return (String)get(Constants.PR_CERTIFICATE_TYPE);
    }

    public void setCertType(String str) {
        put(Constants.PR_CERTIFICATE_TYPE, str);
    }

    public String getReqFormat(String certType) {
         return (String)get(certType+ConfigConstants.PR_REQUEST_FORMAT);
    }

    public void setReqFormat(String certType, String str) {
        put(certType+ConfigConstants.PR_REQUEST_FORMAT , str);
    }

    public boolean isNewRequest() {
		String val = (String)get(getCertType()+"new");
        if (val != null && val.equals(Constants.TRUE))
            return true;
        return false;
    }

    public void setNewRequest() {
        put(getCertType()+"new", Constants.TRUE);
    }

    public boolean isCAReqResultDisplayed() {
		String val = (String)get(ConfigConstants.CA_REQUEST_DISPLAYED);
        if (val != null && val.equals(Constants.TRUE))
            return true;
        return false;
    }

    public void setCAReqResultDisplayed(String val) {
        put(ConfigConstants.CA_REQUEST_DISPLAYED, val);
    }

    public boolean isRAReqResultDisplayed() {
		String val = (String)get(ConfigConstants.RA_REQUEST_DISPLAYED);
        if (val != null && val.equals(Constants.TRUE))
            return true;
        return false;
    }

    public void setRAReqResultDisplayed(String val) {
        put(ConfigConstants.RA_REQUEST_DISPLAYED, val);
    }

    public boolean isOCSPReqResultDisplayed() {
		String val = (String)get(ConfigConstants.OCSP_REQUEST_DISPLAYED);
        if (val != null && val.equals(Constants.TRUE))
            return true;
        return false;
    }

    public void setOCSPReqResultDisplayed(String val) {
        put(ConfigConstants.OCSP_REQUEST_DISPLAYED, val);
    }

    public boolean isKRAReqResultDisplayed() {
		String val = (String)get(ConfigConstants.KRA_REQUEST_DISPLAYED);
        if (val != null && val.equals(Constants.TRUE))
            return true;
        return false;
    }

    public void setKRAReqResultDisplayed(String val) {
        put(ConfigConstants.KRA_REQUEST_DISPLAYED, val);
    }

    public boolean isSSLReqResultDisplayed() {
		String val = (String)get(ConfigConstants.SSL_REQUEST_DISPLAYED);
        if (val != null && val.equals(Constants.TRUE))
            return true;
        return false;
    }

    public void setSSLReqResultDisplayed(String val) {
        put(ConfigConstants.SSL_REQUEST_DISPLAYED, val);
    }

    public String getCertRequest() {
        return (String)get(Constants.PR_CERT_REQUEST);
    }

    public void setCertRequest(String certReq) {
        put(Constants.PR_CERT_REQUEST, certReq);
    }

    public String getCAKeyLength() {
        return (String)get(CA_KEY_LEN);
    }

    public String getCATokenName() {
        return (String)get(CA_TOKEN_NAME);
    }

    public void setCATokenName(String tokenname) {
        put(CA_TOKEN_NAME, tokenname);
    }

    public String getOCSPTokenName() {
        return (String)get(OCSP_TOKEN_NAME);
    }

    public void setOCSPTokenName(String tokenname) {
        put(OCSP_TOKEN_NAME, tokenname);
    }

    public String getRATokenName() {
        return (String)get(RA_TOKEN_NAME);
    }

    public void setRATokenName(String tokenname) {
        put(RA_TOKEN_NAME, tokenname);
    }

    public String getKRATokenName() {
        return (String)get(KRA_TOKEN_NAME);
    }

    public void setKRATokenName(String tokenname) {
        put(KRA_TOKEN_NAME, tokenname);
    }

    public String getSSLTokenName() {
        return (String)get(SSL_TOKEN_NAME);
    }

    public void setSSLTokenName(String tokenname) {
        put(SSL_TOKEN_NAME, tokenname);
    }

    public String getMigrateCACertTokenName() {
        return (String)get(MIGRATE_CA_TOKEN_NAME);
    }

    public void setMigrateCACertTokenName(String tokenname) {
        put(MIGRATE_CA_TOKEN_NAME, tokenname);
    }

    public String getMigrateSSLCertTokenName() {
        return (String)get(MIGRATE_SSL_TOKEN_NAME);
    }

    public void setMigrateSSLCertTokenName(String tokenname) {
        put(MIGRATE_SSL_TOKEN_NAME, tokenname);
    }

    public String getTokenName() {
        return (String)get(ConfigConstants.PR_TOKEN_NAME);
    }

    public String getTokensList() {
        return (String)get(ConfigConstants.PR_TOKEN_NAMES);
    }

    public String getTokensInit() {
        return (String)get(ConfigConstants.PR_TOKEN_INITIALIZED);
    }

    public String getTokensLogin() {
        return (String)get(ConfigConstants.PR_TOKEN_LOGGED_IN);
    }

    public void setKeyLength(String val) {
        put(ConfigConstants.PR_KEY_LEN, val);
    }

    public String getKeyLength() {
        String val = (String)get(ConfigConstants.PR_KEY_LEN);
        if (val == null)
            val = "512";
        return val;
    }

    public String getKeyCurveName() {
        String val = (String)get(ConfigConstants.PR_KEY_CURVENAME);
        if (val ==null)
            val = "nistp521";
        return val;
    }

    public void setKeyCurveName(String val) {
        put(ConfigConstants.PR_KEY_CURVENAME, val);
    }

    public String getKeyType() {
        String type = (String)get(ConfigConstants.PR_KEY_TYPE);
		// work around the historical mistake,
		// not touching files around the places.
		if ( type == null || type.equals("")) {
			String certType = getCertType();
			if (certType.equals(Constants.PR_CA_SIGNING_CERT)) {
				type = (String)get("ca_keyType");
			} else if (certType.equals(Constants.PR_RA_SIGNING_CERT)) {
				type = (String)get("ra_keyType");
			} else if (certType.equals(Constants.PR_OCSP_SIGNING_CERT)) {
				type = (String)get("ocsp_keyType");
			} else if (certType.equals(Constants.PR_KRA_TRANSPORT_CERT)) {
				type = (String)get("kra_keyType");
			} else if (certType.equals(Constants.PR_SERVER_CERT)) {
				type = (String)get("ssl_keyType");
			}
		}
		return type;
    }

    public String getSubjectName() {
        return (String)get(ConfigConstants.PR_SUBJECT_NAME);
    }

    public void setSubjectName(String str) {
        put(ConfigConstants.PR_SUBJECT_NAME, str);
    }

    public String getCASubjectName() {
        return (String)get(ConfigConstants.PR_CA_SUBJECT_NAME);
    }

    public void setCASubjectName(String str) {
        put(ConfigConstants.PR_CA_SUBJECT_NAME, str);
    }

    public String getRASubjectName() {
        return (String)get(ConfigConstants.PR_RA_SUBJECT_NAME);
    }

    public void setRASubjectName(String str) {
        put(ConfigConstants.PR_RA_SUBJECT_NAME, str);
    }

    public String getOCSPSubjectName() {
        return (String)get(ConfigConstants.PR_OCSP_SUBJECT_NAME);
    }

    public void setOCSPSubjectName(String str) {
        put(ConfigConstants.PR_OCSP_SUBJECT_NAME, str);
    }

    public String getKRASubjectName() {
        return (String)get(ConfigConstants.PR_KRA_SUBJECT_NAME);
    }

    public void setKRASubjectName(String str) {
        put(ConfigConstants.PR_KRA_SUBJECT_NAME, str);
    }

    public String getSSLSubjectName() {
        return (String)get(ConfigConstants.PR_SSL_SUBJECT_NAME);
    }

    public void setSSLSubjectName(String str) {
        put(ConfigConstants.PR_SSL_SUBJECT_NAME, str);
    }

    public NameValuePairs getAllCertInfo() {
        return (NameValuePairs)get(ALL_CERT_INFO);
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

    public boolean isSingleSignon() {
        String val = (String)get(ConfigConstants.PR_SINGLE_SIGNON);
        if (val != null && val.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isCACertLocalCA() {
        String val = (String)get(ConfigConstants.PR_CACERT_LOCALCA);
        if (val == null) {
            return true;
        }
        else if (val.equals(Constants.TRUE)) {
            return true;
        }
        return false;
    }

    // set true or false
    public void setCACertLocalCA(String val) {
        put(ConfigConstants.PR_CACERT_LOCALCA, val);
    }

    public boolean isRACertLocalCA() {
        String val = (String)get(ConfigConstants.PR_RACERT_LOCALCA);
        if (val == null)
            return true;
        else if (val.equals(Constants.TRUE))
            return true;
        return false;
    }

    // set true or false
    public void setRACertLocalCA(String val) {
        put(ConfigConstants.PR_RACERT_LOCALCA, val);
    }

    public boolean isOCSPCertLocalCA() {
        String val = (String)get(ConfigConstants.PR_OCSPCERT_LOCALCA);
        if (val == null)
            return true;
        else if (val.equals(Constants.TRUE))
            return true;
        return false;
    }

    // set true or false
    public void setOCSPCertLocalCA(String val) {
        put(ConfigConstants.PR_OCSPCERT_LOCALCA, val);
    }

    public boolean isKRACertLocalCA() {
        String val = (String)get(ConfigConstants.PR_KRACERT_LOCALCA);
        if (val == null)
            return true;
        else if (val.equals(Constants.TRUE))
            return true;
        return false;
    }

    // set true or false
    public void setKRACertLocalCA(String val) {
        put(ConfigConstants.PR_KRACERT_LOCALCA, val);
    }

    public boolean isSSLCertLocalCA() {
        String val = (String)get(ConfigConstants.PR_SSLCERT_LOCALCA);
        if (val == null || val.equals(""))
            return true;
        else if (val.equals(Constants.TRUE))
            return true;
        return false;
    }

    // set true or false
    public void setSSLCertLocalCA(String val) {
        put(ConfigConstants.PR_SSLCERT_LOCALCA, val);
    }

    public void setInstallCertNow(String val) {
        put(INSTALLCERT_NOW, val);
    }

    public boolean isInstallCertNow() {
        String val = (String)get(INSTALLCERT_NOW);
        if (val == null)
            return false;
        else if (val.equals(Constants.TRUE))
            return true;
        return false;
    }

    public String getCertContent() {
        return (String)get(Constants.PR_CERT_CONTENT);
    }

    public String getNickname() {
        return (String)get(Constants.PR_NICKNAME);
    }

    public String getCertOrder() {
        return (String)get(ConfigConstants.PR_CERT_CONTENT_ORDER);
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

    public String getMachineName() {
        return (String)get(ConfigConstants.PR_MACHINE_NAME);
    }

    public void setEnableMigration(String val) {
        put(ConfigConstants.PR_ENABLE_MIGRATION, val);
    }

    public boolean isMigrationEnable() {
        String val = (String)get(ConfigConstants.PR_ENABLE_MIGRATION);
        if (val != null && val.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public void setMigrationOutputPath(String path) {
        put(ConfigConstants.PR_OUTPUT_PATH, path);
    }

    public String getMigrationOutputPath() {
        return (String)get(ConfigConstants.PR_OUTPUT_PATH);
    }

    public void setInternalDBPasswd(String passwd) {
        put(ConfigConstants.PR_DB_PWD, passwd);
    }

    public String getInternalDBPasswd() {
        return (String)get(ConfigConstants.PR_DB_PWD);
    }

    public void setMigrationPasswd(String val) {
        put(ConfigConstants.PR_MIGRATION_PASSWORD, val);
    }

    public String getMigrationPasswd() {
        return (String)get(ConfigConstants.PR_MIGRATION_PASSWORD);
    }

    public void setSigningKeyMigrationToken(String tokenname) {
        put(ConfigConstants.PR_SIGNING_KEY_MIGRATION_TOKEN, tokenname);
    }

    public String getSigningKeyMigrationToken() {
        return (String)get(ConfigConstants.PR_SIGNING_KEY_MIGRATION_TOKEN);
    }

    public void setSSLKeyMigrationToken(String tokenname) {
        put(ConfigConstants.PR_SSL_KEY_MIGRATION_TOKEN, tokenname);
    }

    public String getSSLKeyMigrationToken() {
        return (String)get(ConfigConstants.PR_SSL_KEY_MIGRATION_TOKEN);
    }

    public void setSigningKeyMigrationPasswd(String val) {
        put(ConfigConstants.PR_SIGNING_KEY_MIGRATION_TOKEN_PASSWD, val);
    }

    public String getSigningKeyMigrationPasswd() {
        return (String)get(ConfigConstants.PR_SIGNING_KEY_MIGRATION_TOKEN_PASSWD);
    }

    public void setSigningKeyMigrationSOPPasswd(String val) {
        put(ConfigConstants.PR_SIGNING_KEY_MIGRATION_TOKEN_SOPPASSWD, val);
    }

    public String getSigningKeyMigrationSOPPasswd() {
        return (String)get(ConfigConstants.PR_SIGNING_KEY_MIGRATION_TOKEN_SOPPASSWD);
    }

    public void setSSLKeyMigrationPasswd(String val) {
        put(ConfigConstants.PR_SSL_KEY_MIGRATION_TOKEN_PASSWD, val);
    }

    public String getSSLKeyMigrationPasswd() {
        return (String)get(ConfigConstants.PR_SSL_KEY_MIGRATION_TOKEN_PASSWD);
    }

    public void setSSLKeyMigrationSOPPasswd(String val) {
        put(ConfigConstants.PR_SSL_KEY_MIGRATION_TOKEN_SOPPASSWD, val);
    }

    public String getSSLKeyMigrationSOPPasswd() {
        return (String)get(ConfigConstants.PR_SSL_KEY_MIGRATION_TOKEN_SOPPASSWD);
    }

    public void setInstalledOCSP(String val) {
        put(ConfigConstants.PR_OCSP, val);
    }

    public void setInstalledCA(String val) {
        put(ConfigConstants.PR_CA, val);
    }

    public boolean isOCSPInstalled() {
        String str = (String)get(ConfigConstants.PR_OCSP);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public boolean isCAInstalled() {
        String str = (String)get(ConfigConstants.PR_CA);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public void setInstalledRA(String val) {
        put(ConfigConstants.PR_RA, val);
    }

    public boolean isRAInstalled() {
        String str = (String)get(ConfigConstants.PR_RA);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public void setInstalledKRA(String val) {
        put(ConfigConstants.PR_KRA, val);
    }

    public void setInstalledTKS(String val) {
        put(ConfigConstants.PR_TKS, val);
    }

    public boolean isKRAInstalled() {
        String str = (String)get(ConfigConstants.PR_KRA);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }
    public boolean isTKSInstalled() {
        String str = (String)get(ConfigConstants.PR_TKS);
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }
    public boolean isOCSPServiceAdded() {
        String str = (String)get(ConfigConstants.PR_CA_OCSP_SERVICE);
        if (str == null || str.equals(ConfigConstants.FALSE))
            return false;
        return true;
    }

    public void setOCSPService(String val) {
        put(ConfigConstants.PR_CA_OCSP_SERVICE, val);
    }

    public void setCMHost(String host) {
        put(ConfigConstants.CA_HOST, host);
    }

    public String getCMHost() {
        return (String)get(ConfigConstants.CA_HOST);
    }

    public void setCMPort(String port) {
        put(ConfigConstants.CA_PORT, port);
    }

    public String getCMPort() {
        return (String)get(ConfigConstants.CA_PORT);
    }

    public void setCMTimeout(String timeout) {
        put(ConfigConstants.CA_TIMEOUT, timeout);
    }

    public String getCMTimeout() {
        return (String)get(ConfigConstants.CA_TIMEOUT);
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
        put(getCertType()+ConfigConstants.PR_REQUEST_ID, requestID);
    }

    public String getRequestID() {
        return (String)get(getCertType()+ConfigConstants.PR_REQUEST_ID);
    }

    public void setX509RequestStatus(String requestStatus) {
        put("x509"+ConfigConstants.PR_CERT_REQUEST+"Status", requestStatus);
    }

    public String getX509RequestStatus() {
        return (String)get("x509"+ConfigConstants.PR_CERT_REQUEST+"Status");
    }

    public void setX509RequestID(String requestID) {
        put("x509"+getCertRequest()+ConfigConstants.PR_CERT_REQUEST, requestID);
    }

    public String getX509RequestID() {
        return (String)get("x509"+getCertRequest()+ConfigConstants.PR_CERT_REQUEST);
    }

    public void setRequestSent(boolean sent) {
		if (sent)
			put(getCertRequest()+"Sent", ConfigConstants.TRUE);
		else
			put(getCertRequest()+"Sent", ConfigConstants.FALSE);
    }

    public boolean requestSent() {
        String str = (String)get(getCertRequest()+"Sent");
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        return false;
    }

    public void setRequestError(String error) {
		put(getCertRequest()+"Error", error);
    }

    public String getRequestError() {
        return (String)get(getCertRequest()+"Error");
    }

    public void setImportError(String error) {
		put(getCertType()+"Error", error);
    }

    public String getImportError() {
        return (String)get(getCertType()+"Error");
    }

    public void setX509RequestError(String error) {
		put("x509"+getCertRequest()+"Error", error);
    }

    public String getX509RequestError() {
        return (String)get("x509"+getCertRequest()+"Error");
    }

    public void setDRMHost(String host) {
        put(ConfigConstants.KRA_HOST, host);
    }

    public String getDRMHost() {
        return (String)get(ConfigConstants.KRA_HOST);
    }

    public void setDRMPort(String port) {
        put(ConfigConstants.KRA_PORT, port);
    }

    public String getDRMPort() {
        return (String)get(ConfigConstants.KRA_PORT);
    }

    public void setDRMTimeout(String timeout) {
        put(ConfigConstants.KRA_TIMEOUT, timeout);
    }

    public String getDRMTimeout() {
        return (String)get(ConfigConstants.KRA_TIMEOUT);
    }

    public void enableRemoteDRM(String enable) {
        put(ConfigConstants.REMOTE_KRA_ENABLED, enable);
    }

    public boolean isRemoteDRM() {
        String value = (String)get(ConfigConstants.REMOTE_KRA_ENABLED);
        if (value == null || value.equals("") || value.equals(ConfigConstants.FALSE) ||
          !value.equals(ConfigConstants.TRUE))
            return false;
        return true;
    }

    public String getSingleSignon() {
        return (String)get(ConfigConstants.PR_SINGLE_SIGNON);
    }

    public void setRequiredAgents(String val) {
        put(ConfigConstants.PR_AGENT_M, val);
    }

    public String getRequiredAgents() {
        return (String)get(ConfigConstants.PR_AGENT_M);
    }

    public void setTotalAgents(String val) {
        put(ConfigConstants.PR_AGENT_N, val);
    }

    public String getTotalAgents() {
        return (String)get(ConfigConstants.PR_AGENT_N);
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

    public String getCAKeyType() {
        return (String)get(ConfigConstants.PR_CA_KEYTYPE);
    }

	public boolean hasEntireCAChain() {
        String str = (String)get(Constants.PR_CA_SIGNING_CERT+
			"hasEntireChain");
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        else
            return false;
	}

	public boolean hasEntireSSLChain() {
        String str = (String)get(Constants.PR_SERVER_CERT+
			"hasEntireChain");
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        else
            return false;
	}

	public boolean hasEntireKRAChain() {
        String str = (String)get(Constants.PR_KRA_TRANSPORT_CERT+
			"hasEntireChain");
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        else
            return false;
	}

	public boolean hasEntireOCSPChain() {
        String str = (String)get(Constants.PR_OCSP_SIGNING_CERT+
			"hasEntireChain");
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        else
            return false;
	}

	public boolean hasEntireRAChain() {
        String str = (String)get(Constants.PR_RA_SIGNING_CERT+
			"hasEntireChain");
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        else
            return false;
	}

    public String getOComponent() {
        return (String)get(ConfigConstants.PR_O_COMPONENT);
    }

    public void setOComponent(String str) {
        put(ConfigConstants.PR_O_COMPONENT, str);
    }

    public String getOUComponent() {
        return (String)get(ConfigConstants.PR_OU_COMPONENT);
    }

    public void setOUComponent(String str) {
        put(ConfigConstants.PR_OU_COMPONENT, str);
    }

    public String getLComponent() {
        return (String)get(ConfigConstants.PR_L_COMPONENT);
    }

    public void setLComponent(String str) {
        put(ConfigConstants.PR_L_COMPONENT, str);
    }

    public String getSTComponent() {
        return (String)get(ConfigConstants.PR_ST_COMPONENT);
    }

    public void setSTComponent(String str) {
        put(ConfigConstants.PR_ST_COMPONENT, str);
    }

    public String getCComponent() {
        return (String)get(ConfigConstants.PR_C_COMPONENT);
    }

    public void setCComponent(String str) {
        put(ConfigConstants.PR_C_COMPONENT, str);
    }

    public String getCAOComp() {
        String str = (String)get(ConfigConstants.PR_CA_O_COMPONENT);
        return str;
    }

    public void setCAOComp(String str) {
        put(ConfigConstants.PR_CA_O_COMPONENT, str);
    }

    public String getCACComp() {
        String str = (String)get(ConfigConstants.PR_CA_C_COMPONENT);
        return str;
    }

    public void setCACComp(String str) {
        put(ConfigConstants.PR_CA_C_COMPONENT, str);
    }

    public String getOCSPOComp() {
        String str = (String)get(ConfigConstants.PR_OCSP_O_COMPONENT);
        return str;
    }

    public void setOCSPOComp(String str) {
        put(ConfigConstants.PR_OCSP_O_COMPONENT, str);
    }

    public String getRAOComp() {
        String str = (String)get(ConfigConstants.PR_RA_O_COMPONENT);
        return str;
    }

    public void setRAOComp(String str) {
        put(ConfigConstants.PR_RA_O_COMPONENT, str);
    }

    public String getOCSPCComp() {
        String str = (String)get(ConfigConstants.PR_OCSP_C_COMPONENT);
        return str;
    }

    public void setOCSPCComp(String str) {
        put(ConfigConstants.PR_OCSP_C_COMPONENT, str);
    }

    public String getRACComp() {
        String str = (String)get(ConfigConstants.PR_RA_C_COMPONENT);
        return str;
    }

    public void setRACComp(String str) {
        put(ConfigConstants.PR_RA_C_COMPONENT, str);
    }

    public String getCertRequestDir() {
        return (String)get(Constants.PR_CERT_REQUEST_DIR);
    }

    public void setCASerialNumber(String str) {
        put(ConfigConstants.PR_CA_SERIAL_NUMBER, str);
    }
	public void setRequestNumber(String str) {
        put(ConfigConstants.PR_REQUEST_NUMBER, str);
    }

    public String getCASerialNumber() {
        return (String)get(ConfigConstants.PR_CA_SERIAL_NUMBER);
    }
    public String getRequestNumber() {
        return (String)get(ConfigConstants.PR_REQUEST_NUMBER);
    }

    public void clearRequestNumber() {
        remove(ConfigConstants.PR_REQUEST_NUMBER);
    }

    public void setCAEndSerialNumber(String str) {
        put(ConfigConstants.PR_CA_ENDSERIAL_NUMBER, str);
    }

    public String getCAEndSerialNumber() {
        return (String)get(ConfigConstants.PR_CA_ENDSERIAL_NUMBER);
    }

    public void clearCAEndSerialNumber() {
        remove(ConfigConstants.PR_CA_ENDSERIAL_NUMBER);
    }
    public String getEndRequestNumber() {
        return (String)get(ConfigConstants.PR_ENDREQUEST_NUMBER);
    }

    public boolean isCloning() {
        String str = (String)get("cloning");
        if (str != null && str.equals(ConfigConstants.TRUE))
            return true;
        else
            return false;
    }
     public void setCloning(String str) {
        put("cloning", str);
    }
     public void setCLAHost(String host) {
        put(ConfigConstants.CLA_HOST, host);
    }

    public String getCLAHost() {
        return (String)get(ConfigConstants.CLA_HOST);
    }

    public void setCLAPort(String port) {
        put(ConfigConstants.CLA_PORT, port);
    }

    public String getCLAPort() {
        return (String)get(ConfigConstants.CLA_PORT);
    }

    public void setCLAPortEE(String port) {
        put(ConfigConstants.CLA_PORT_EE, port);
    }

    public String getCLAPortEE() {
        return (String)get(ConfigConstants.CLA_PORT_EE);
    }

    public void setCLATimeout(String timeout) {
        put(ConfigConstants.CLA_TIMEOUT, timeout);
    }

    public String getCLATimeout() {
        return (String)get(ConfigConstants.CLA_TIMEOUT);
    }

    public boolean isConnectDBDone() {
        String val = (String)get(ConfigConstants.STAGE_CONNECT_DB);
        if (val == null || val.equals("") || val.equals(ConfigConstants.FALSE))
            return false;
        return true;
    }

    public void setConnectDBDone(String s) {
        put(ConfigConstants.STAGE_CONNECT_DB, s);
    }

    public boolean isCreateDBDone() {
        String val = (String)get(ConfigConstants.STAGE_INTERNAL_DB);
        if (val == null || val.equals("") || val.equals(ConfigConstants.FALSE))
            return false;
        return true;
    }

    public void setCreateDBDone(String s) {
        put(ConfigConstants.STAGE_INTERNAL_DB, s);
    }

    public boolean isWebServerDone() {
        String val = (String)get(ConfigConstants.STAGE_CONFIG_WEBSERVER);
        if (val == null || val.equals("") || val.equals(ConfigConstants.FALSE))
            return false;
        return true;
    }

    public void setWebServerDone(String str) {
        put(ConfigConstants.STAGE_CONFIG_WEBSERVER, str);
    }

    public boolean isOCSPServiceDone() {
        String val = (String)get(ConfigConstants.STAGE_OCSP_SERVICE_ADDED);
        if (val == null || val.equals("") || val.equals(ConfigConstants.FALSE))
            return false;
        return true;
    }

   public boolean isCACertRequestSucc() {
        String str = (String)get(ConfigConstants.STAGE_CA_REQ_SUCCESS);
        if (str == null || str.equals("") || str.equals(ConfigConstants.FALSE))
            return false;
        return true;
    }

   public boolean isRACertRequestSucc() {
        String str = (String)get(ConfigConstants.STAGE_RA_REQ_SUCCESS);
        if (str == null || str.equals("") || str.equals(ConfigConstants.FALSE))
            return false;
        return true;
    }

   public boolean isKRACertRequestSucc() {
        String str = (String)get(ConfigConstants.STAGE_KRA_REQ_SUCCESS);
        if (str == null || str.equals("") || str.equals(ConfigConstants.FALSE))
            return false;
        return true;
    }

   public boolean isSSLCertRequestSucc() {
        String str = (String)get(ConfigConstants.STAGE_SSL_REQ_SUCCESS);
        if (str == null || str.equals("") || str.equals(ConfigConstants.FALSE))
            return false;
        return true;
    }

   public boolean isOCSPCertRequestSucc() {
        String str = (String)get(ConfigConstants.STAGE_OCSP_REQ_SUCCESS);
        if (str == null || str.equals("") || str.equals(ConfigConstants.FALSE))
            return false;
        return true;
    }
}

