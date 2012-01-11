package com.netscape.pkisilent.common;

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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Properties;

/**
 * CMS Test Framework.
 * Use this class to Configure a CA, RA,DRM,OCSP and SubCA subsystem.
 * This simulartes the installation wizard functions and helps to configure a CMS subsystem.
 */

public class AutoInstaller {

    private static Properties props = null;

    // Admin Server and InternalDB varialbes 
    private String adminDomain, adminID, adminPWD, adminPort, machineName, host, serverID, instanceID, serverRoot,
            sieURL, dbConnPort, dbConnHost, dbInstanceName, dbPassword, dbLDAPauthDN, dbmode, ldapServerDB;

    // CMS Subsystem info

    private String certAdminName, certAdminUid, certAdminPWD, kra, subsystems, ca, ra, ocsp, remoteKRA,
            wirelessSupport, eeHttpPort, eeHttpsPort, agentHttpsPort, radminHttpsPort, tokenName, tokenPWD, certType,
            keyType, keyLength, SingleSignOnPWD, subjectName, aki, isCA, ski, sslCABit, objectSigningCABit, mailCABit,
            hashType, caOComponent, certValidityDays, signingCert, tks;

    // CA info
    private String caHostname, caPortnum, caTimeout, caEEPort, enpropfile, cdir, tokenpwd, CAadminId, CAadminPwd,
            CAcertnickname, caAgentPortnum, cloneInstanceId;

    // Program variables 
    private int i;
    private String configURL, deamonURL, certInstID;
    private String inputLine;
    private boolean st = false;

    private String postQuery = null;
    private String propFileName;
    private StringBuffer spage = new StringBuffer();
    // 4.5 server String CERTtokenName="Internal Key Storage Token";
    private String CERTtokenName = "internal";

    private String certRequestStr = null, ssl_clientcert = "true";

    private String raSigningCert = null;
    private String kraTransportCert = null;

    private boolean subca = false;

    // / Constructors 

    public AutoInstaller() {
    }

    /**
     * Constructor . Takes parameter Server Root .
     */
    public AutoInstaller(String sr) {
        serverRoot = sr;
    }

    // Set InternalDBVInfo
    /**
     * Set Internal Database Information . Takes parameters internaldatabase hostname, internaldatabase port,
     * internaldatabase name, internaldatabase binddn, internaldatabase password
     */

    public void setInternalDBInfo(String dbh, String dbp, String dbname, String dbdn, String dbpswd) {
        dbConnPort = dbp;
        dbConnHost = dbh;
        dbInstanceName = dbname;
        dbPassword = dbpswd;
        dbLDAPauthDN = dbdn;
        dbmode = "local";
        ldapServerDB = "userRoot";
    }

    // Create Password file 
    private boolean CreatePasswordFile() {
        String s = "internal: " + SingleSignOnPWD;
        OutputStream f0 = null;

        try {
            f0 = new FileOutputStream(
                    serverRoot + "/" + instanceID + "/config/password.conf");

            f0.write(s.getBytes());
            f0.close();
            return true;
        } catch (Exception e) {
            System.out.println("exception " + e.getMessage());
            try {
                if (f0 != null)
                    f0.close();
            } catch (IOException ioe) {
                System.out.println("IO Exception: " + ioe.getMessage());
            }
            return false;
        }

    }

    private boolean BackupConfigFile() {
        FileInputStream f1 = null;
        OutputStream f2 = null;
        try {
            f1 = new FileInputStream(
                    serverRoot + "/" + instanceID + "/config/CS.cfg");
            int size = f1.available();
            byte b[] = new byte[size];

            if (f1.read(b) != b.length) {
                f1.close();
                return false;
            }
            f2 = new FileOutputStream(
                    serverRoot + "/" + instanceID + "/config/CS.cfg.org");

            f2.write(b);

            f1.close();
            f2.close();
            return true;
        } catch (Exception e) {
            System.out.println("exception " + e.getMessage());
            try {
                if (f1 != null)
                    f1.close();
            } catch (IOException ioe) {
                System.out.println("IO Exception: " + ioe.getMessage());
            }
            try {
                if (f2 != null)
                    f2.close();
            } catch (IOException ioe) {
                System.out.println("IO Exception: " + ioe.getMessage());
            }
            return false;
        }

    }

    // Get RaSigning Cert 

    public String getRASigningCert() {
        return raSigningCert;
    }

    // Get KRATransportCert
    public String getKRATransportCert() {
        return kraTransportCert;
    }

    // Set Admin Server Info

    /**
     * Set Admin Server Information . Takes parameters : hostname, adminserver portnumber , adminId , adminPassword
     */
    public void setAdminInfo(String h, String p, String adDN, String id, String adpwd) {
        adminDomain = adDN;
        adminID = id;
        adminPWD = adpwd;
        adminPort = p;
        host = h;

    }

    // Set CA Server Info 
    /**
     * Set CA server Information . Takes parametrers :CAhostname, CAEEPORT, CAAGENTPORT , CAAdminUID, CAAdminPassword
     */

    public void setCAInfo(String cah, String caeep, String caagp, String caaduid, String caadpwd) {
        caHostname = cah;
        caPortnum = caagp;
        caTimeout = "30";
        caEEPort = caeep;
        CAadminId = caaduid;
        CAadminPwd = caadpwd;
        caAgentPortnum = caagp;

    }

    // Set ClientDB Info;
    /**
     * Sets Client Database information . Takes paramters : certdbdir, certdbpasswd, certnickanme
     */

    public void setClientDBInfo(String cd, String pwd, String nickname) {

        cdir = cd;
        tokenpwd = pwd;
        CAcertnickname = nickname;
    }

    // Is this Internal or any hardware token and its password;
    /**
     * Set token info . Takes paramter "Internal" and tokenpasswd
     */
    public void setTokenInfo(String t, String tp) {

        tokenName = t;
        tokenPWD = tp;

    }

    // Set Subsystem Information for Configuring 

    /**
     * Takes parameters - sID- ServerID e.x cert1, sRoot- ServerRootK kT- keyType "RSA/DSA" , kL - keylength (1024.2048)
     * , cVD- certificate validity dates e.g 365 for 1 year, sdn - subsystems dn, sAdp - subsystem's Admin port, sAgp -
     * subsystems's Agentport,seSP- subsystem's ee SSL port , sep- Subsystems ee port.
     */

    public void setSubSystemInfo(String sID, String sRoot, String kT, String kL, String hT, String cVD, String sdn,
            String sAdP, String sAgP, String seSP, String seP) {
        serverID = sID;
        instanceID = "cert-" + sID;

        keyType = kT;
        keyLength = kL;
        hashType = hT;
        certValidityDays = cVD;

        eeHttpPort = seP;
        eeHttpsPort = seSP;
        agentHttpsPort = sAgP;
        radminHttpsPort = sAdP;
        subjectName = sdn;
        caOComponent = "test";
    }

    // // Configure CMS Subsystems 

    /**
     * Confiures a CA Subsystem .Takes parameter : adminSubjectDN, adminUID, AdminPasswd, SingleSignonPasswd
     */
    public boolean ConfigureCA(String adn, String aduid, String adp, String ssonpwd) {
        certAdminName = adn;
        certAdminUid = aduid;
        certAdminPWD = adp;
        SingleSignOnPWD = ssonpwd;

        signingCert = "caSigningCert";
        certType = signingCert;
        subsystems = "ca";
        ca = "true";
        kra = "false";
        ra = "false";
        ocsp = "false";
        remoteKRA = "false";
        wirelessSupport = "false";
        aki = "true";
        isCA = "true";
        ski = "true";
        sslCABit = "true";
        objectSigningCABit = "true";
        mailCABit = "true";

        if (ConfCA()) {
            CreatePasswordFile();
            BackupConfigFile();
            return true;
        }

        return false;

    }

    public boolean ConfigureTKS(String adn, String aduid, String adp, String ssonpwd) {

        certAdminName = adn;
        certAdminUid = aduid;
        certAdminPWD = adp;
        SingleSignOnPWD = ssonpwd;
        signingCert = "raSigningCert";
        certType = signingCert;
        subsystems = "tks";
        ra = "false";
        tks = "true";
        kra = "false";
        ca = "false";
        ocsp = "false";
        remoteKRA = "false";
        wirelessSupport = "false";
        aki = "true";
        isCA = "false";
        ski = "true";
        sslCABit = "true";
        objectSigningCABit = "true";
        mailCABit = "true";

        if (ConfTKS()) {
            CreatePasswordFile();
            BackupConfigFile();
            return true;
        }

        return false;

    }

    private boolean ConfTKS() {
        // Start Configuring 

        // Step 1. Start Deamon

        if (!startDeamon()) {
            System.out.println(
                    "Configuring Cert Instance: Unable to start deamon");
            return false;
        }

        // Sometimes it takes time to start deamon so wait for few seconds
        try {
            System.out.println("going to sleep for 10 seconds");
            Thread.sleep(10000);
        } catch (InterruptedException ie) {
            System.out.println("sleep exection");
        }

        // Step 1a: Initialize Token ( Changed in 6.0)jjj
        if (!initializePWD()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing pwd token");
            return false;
        }

        // Step 2. Configure Internal DB
        if (!configInternalDB()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring internal db");
            return false;
        }

        // Step 3. Create Admin Values 
        if (!createAdminValues()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring admin values ");
            return false;
        }

        // Step 4. SubSystems 

        if (!selectSubSystem()) {
            System.out.println(
                    "Configuring Cert Instance: error selecting subsystems");
            return false;
        }

        // Step 5. Network Configuration
        if (!networkConfig()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring network ports ");
            return false;
        }

        // Create a SSL signing cert
        Date tmpdate = new Date();

        certType = "serverCert";
        subjectName = "CN=" + host + "." + adminDomain + ",OU=ssltest"
                + tmpdate.getTime() + ",O=SSL,C=US";
        keyLength = "512";
        keyType = "RSA";
        String mtokenPWD = tokenPWD;

        tokenPWD = "";
        ssl_clientcert = "false";
        signingCert = "server";

        if (!initializeToken()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing token");
            return false;
        }

        // Step 8 : keyLenth
        if (!keyLength()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring KeyLength");
            return false;
        }

        // Step 9 : CheckDN 
        if (!checkDN()) {
            System.out.println(
                    "Configuring Cert Instance: error checking deamon");
            return false;
        }

        // Step 10 :
        if (!certRequest(false)) {
            System.out.println(
                    "Configuring Cert Instance: error creating Request");
            return false;
        }

        // After creating ssl cert 
        tokenPWD = mtokenPWD;

        // Step 11 
        if (!singleSignON()) {
            System.out.println(
                    "Configuring Cert Instance: error setting up singlesignon");
            return false;
        }

        // Step 11 
        if (!doMisc()) {
            System.out.println(
                    "Configuring Cert Instance: error setting up miscell");
            return false;
        }

        // Step 12 
        if (!exitDeamon()) {
            System.out.println(
                    "Configuring Cert Instance: Unable to exit deamon");
            return false;
        }

        return true;
    }

    /**
     * Confiures a RA Subsystem .Takes parameter : adminSubjectDN, adminUID, AdminPasswd, SingleSignonPasswd
     */

    public boolean ConfigureRA(String adn, String aduid, String adp, String ssonpwd) {
        certAdminName = adn;
        certAdminUid = aduid;
        certAdminPWD = adp;
        SingleSignOnPWD = ssonpwd;

        signingCert = "raSigningCert";
        certType = signingCert;
        subsystems = "ra";
        ra = "true";
        kra = "false";
        ca = "false";
        ocsp = "false";
        remoteKRA = "false";
        wirelessSupport = "false";
        aki = "true";
        isCA = "true";
        ski = "true";
        sslCABit = "true";
        objectSigningCABit = "true";
        mailCABit = "true";

        if (ConfRA()) {
            CreatePasswordFile();
            BackupConfigFile();
            return true;
        }

        return false;

    }

    /**
     * Confiures a OCSP Subsystem .Takes parameter : adminSubjectDN, adminUID, AdminPasswd, SingleSignonPasswd
     */

    public boolean ConfigureOCSP(String adn, String aduid, String adp, String ssonpwd) {
        certAdminName = adn;
        certAdminUid = aduid;
        certAdminPWD = adp;
        SingleSignOnPWD = ssonpwd;

        signingCert = "ocspSigningCert";
        certType = signingCert;
        subsystems = "ocsp";
        ocsp = "true";
        kra = "false";
        ra = "false";
        ca = "false";
        remoteKRA = "false";
        wirelessSupport = "false";
        aki = "true";
        isCA = "true";
        ski = "true";
        sslCABit = "true";
        objectSigningCABit = "true";
        mailCABit = "true";

        if (ConfOCSP()) {
            CreatePasswordFile();
            BackupConfigFile();
            return true;
        }

        return false;
    }

    /**
     * Confiures a KRA Subsystem .Takes parameter : adminSubjectDN, adminUID, AdminPasswd, SingleSignonPasswd
     */

    public boolean ConfigureKRA(String adn, String aduid, String adp, String ssonpwd) {
        certAdminName = adn;
        certAdminUid = aduid;
        certAdminPWD = adp;
        SingleSignOnPWD = ssonpwd;

        signingCert = "kraTransportCert";
        certType = signingCert;
        subsystems = "kra";
        kra = "true";
        ca = "false";
        ra = "false";
        ocsp = "false";
        remoteKRA = "false";
        wirelessSupport = "false";
        aki = "true";
        isCA = "true";
        ski = "true";
        sslCABit = "true";
        objectSigningCABit = "true";
        mailCABit = "true";
        if (ConfKRA()) {
            CreatePasswordFile();
            BackupConfigFile();
            return true;
        }

        return false;
    }

    /**
     * Confiures a SubCA Subsystem .Takes parameter : adminSubjectDN, adminUID, AdminPasswd, SingleSignonPasswd
     */

    public boolean ConfigureSubCA(String adn, String aduid, String adp, String ssonpwd) {
        certAdminName = adn;
        certAdminUid = aduid;
        certAdminPWD = adp;
        SingleSignOnPWD = ssonpwd;
        subca = true;
        signingCert = "caSigningCert";
        certType = signingCert;
        subsystems = "ca";
        ca = "true";
        kra = "false";
        ra = "false";
        ocsp = "false";
        remoteKRA = "false";
        wirelessSupport = "false";
        aki = "true";
        isCA = "true";
        ski = "true";
        sslCABit = "true";
        objectSigningCABit = "true";
        mailCABit = "true";

        if (ConfSubCA()) {
            CreatePasswordFile();
            BackupConfigFile();
            return true;
        }

        return false;
    }

    // ////////////////////////////////////////////////////////

    private void getProperties(String filePath) throws Exception {
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(filePath);

            props = new Properties();
            props.load(fis);
            System.out.println("Reading Properties file successful");
        } catch (Exception e) {
            System.out.println("exception " + e.getMessage());
        }
        try {
            if (fis != null)
                fis.close();
        } catch (IOException ioe) {
            System.out.println("IO Exception: " + ioe.getMessage());
        }
    }

    private void setPropFile(String fileName) {
        propFileName = fileName;
    }

    private void setConfigURL() {
        configURL = "/" + instanceID + "/Tasks/Operation/config-cert";
    }

    private void setDeamonURL() {
        deamonURL = "/" + instanceID + "/Tasks/Operation/start-daemon";

    }

    private void setPostQueryString(String querystring) {
        postQuery = querystring;
    }

    private boolean Connect(String myStringUrl) {
        // / This functions connects to the URL and POST HTTP Request . 
        // It compares with NMC_STATUS  and return the status.
        System.out.println(myStringUrl);
        st = false;

        PostQuery sm = new PostQuery(myStringUrl, adminID, adminPWD, postQuery);
        boolean st = sm.Send();

        spage = sm.getPage();
        return st;
    }

    private boolean startDeamon() {
        // Set StringURL to connect , set the query string and Connect .Get the result 
        System.out.println("Log Info - configuring Cert Instance : Start Deamon");
        setDeamonURL();
        String myStringUrl = "http://" + host + "." + adminDomain + ":"
                + adminPort + deamonURL;

        System.out.println("Log Info -" + myStringUrl);
        String query = "instanceID=" + URLEncoder.encode(instanceID);

        query += "&AdminUsername=" + URLEncoder.encode(adminID);
        query += "&AdminUserPassword=" + URLEncoder.encode(adminPWD);

        setPostQueryString(query);
        return Connect(myStringUrl);
    }

    private boolean configInternalDB() {

        System.out.println(
                "Log Info - configuring Cert Instance : configureInternalDB");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String query = "serverRoot=" + URLEncoder.encode(serverRoot);

        query += "&instanceID=" + URLEncoder.encode(instanceID);
        query += "&adminUID=" + URLEncoder.encode(adminID);
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("createInternalDB");
        query += "&AdminUserPassword=" + URLEncoder.encode(adminPWD);
        query += "&host=" + URLEncoder.encode(host);
        query += "&internaldb.ldapconn.host=" + URLEncoder.encode(dbConnHost);
        query += "&internaldb.ldapconn.port=" + URLEncoder.encode(dbConnPort);
        query += "&internaldb.ldapauth.bindDN="
                + URLEncoder.encode(dbLDAPauthDN);
        query += "&db.instanceName=" + URLEncoder.encode(dbInstanceName);
        query += "&db.password=" + URLEncoder.encode(dbPassword);
        query += "&adminDomain=" + URLEncoder.encode(adminDomain);
        query += "&db.mode=" + URLEncoder.encode(dbmode);
        query += "&ldapServerDB=" + URLEncoder.encode(ldapServerDB);
        query += "&cmsSeed=0";
        // logging
        setPostQueryString(query);
        return Connect(myStringUrl);

    }

    private boolean createAdminValues() {
        System.out.println("configuring Cert Instance : configureAdmin");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String query = "serverRoot=" + URLEncoder.encode(serverRoot);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&AdminUserPassword=" + URLEncoder.encode(adminPWD);
        query += "&cert.admin.name=" + URLEncoder.encode(certAdminName);
        query += "&cert.admin.uid=" + URLEncoder.encode(certAdminUid);
        query += "&cert.admin.passwd=" + URLEncoder.encode(certAdminPWD);
        query += "&db.password=" + URLEncoder.encode(dbPassword);
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("setupAdmin");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);

    }

    private boolean selectSubSystem() {
        System.out.println("configuring Cert Instance : SubSystems");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String query = "serverRoot=" + URLEncoder.encode(serverRoot);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&AdminUserPassword=" + URLEncoder.encode(adminPWD);
        query += "&db.password=" + URLEncoder.encode(dbPassword);
        query += "&internaldb.ldapauth.bindDN="
                + URLEncoder.encode(dbLDAPauthDN);
        query += "&kra=" + URLEncoder.encode(kra);
        query += "&subsystems=" + URLEncoder.encode(subsystems);
        query += "&ca=" + URLEncoder.encode(ca);
        query += "&ra=" + URLEncoder.encode(ra);
        query += "&ocsp=" + URLEncoder.encode(ocsp);
        query += "&remoteKRA=" + URLEncoder.encode(remoteKRA);
        query += "&wirelessSupport=" + URLEncoder.encode(wirelessSupport);
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("selectSubsystems");
        query += "&cmsSeed=0";

        if (subsystems.equals("ca")) {
            query += "&internaldb.ldapconn.host="
                    + URLEncoder.encode(dbConnHost);
            query += "&internaldb.ldapconn.port="
                    + URLEncoder.encode(dbConnPort);

        }
        if (subsystems.equals("ra")) {
            query += "&caHostname=" + caHostname;
            query += "&caPortnum=" + caPortnum;
            query += "&caTimeout=" + caTimeout;
        }
        if (subsystems.equals("tks")) {
            query += "&tks=true";
        }

        setPostQueryString(query);
        return Connect(myStringUrl);

    }

    private boolean setSerial(String start, String end) {
        System.out.println("configuring Cert Instance : setCASerial");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String query = "serverRoot=" + URLEncoder.encode(serverRoot);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&db.password=" + URLEncoder.encode(dbPassword);
        query += "&caSerialNumber=" + URLEncoder.encode(start);
        query += "&caEndSerialNumber=" + URLEncoder.encode(end);
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("setCASerial");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);
    }

    private boolean setOCSP() {
        System.out.println("configuring Cert Instance : setOCSP");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String query = "serverRoot=" + URLEncoder.encode(serverRoot);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&CAOCSPService=" + URLEncoder.encode("true");
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("addOCSPService");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);
    }

    private boolean networkConfig() {
        System.out.println("configuring Cert Instance : Network Config");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        if (subsystems.equals("kra")) {
            query += "&agentGateway.https.port="
                    + URLEncoder.encode(agentHttpsPort);
            query += "&radm.https.port=" + URLEncoder.encode(radminHttpsPort);
            query += "&eePortsEnable=" + URLEncoder.encode("false");
        } else {
            query += "&eeGateway.http.port=" + URLEncoder.encode(eeHttpPort);
            query += "&eeGateway.https.port=" + URLEncoder.encode(eeHttpsPort);
            query += "&agentGateway.https.port="
                    + URLEncoder.encode(agentHttpsPort);
            query += "&radm.https.port=" + URLEncoder.encode(radminHttpsPort);
            query += "&eePortsEnable=" + URLEncoder.encode("true");
            query += "&eeGateway.http.enable=" + URLEncoder.encode("true");
        }
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("configureNetwork");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);

    }

    private boolean initializePWD() {
        System.out.println("configuring Cert Instance : Initialize token");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&serverRoot=" + URLEncoder.encode(serverRoot);
        query += "&tokenName=" + URLEncoder.encode(tokenName);
        query += "&tokenPasswd=" + URLEncoder.encode(tokenPWD);
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("initToken");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);

    }

    private boolean initializeToken() {
        System.out.println("configuring Cert Instance : Initialize token");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&serverRoot=" + URLEncoder.encode(serverRoot);
        query += "&tokenName=" + URLEncoder.encode(tokenName);
        query += "&tokenPasswd=" + URLEncoder.encode(tokenPWD);
        query += "&certType=" + URLEncoder.encode(certType);
        query += "&keyType=" + URLEncoder.encode(keyType);
        query += "&keyLength=" + URLEncoder.encode(keyLength);
        query += "&sopPasswd=" + URLEncoder.encode(SingleSignOnPWD);
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("initToken");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);

    }

    private boolean keyLength() {
        System.out.println("configuring Cert Instance : Check Key length");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&serverRoot=" + URLEncoder.encode(serverRoot);
        query += "&tokenName=" + URLEncoder.encode(tokenName);
        query += "&tokenPasswd=" + URLEncoder.encode(tokenPWD);
        query += "&certType=" + URLEncoder.encode(certType);
        query += "&keyType=" + URLEncoder.encode(keyType);
        query += "&keyLength=" + URLEncoder.encode(keyLength);
        query += "&sopPasswd=" + URLEncoder.encode(SingleSignOnPWD);
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("checkKeyLength");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);

    }

    private boolean checkDN() {
        System.out.println("configuring Cert Instance : Check DN");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&certType=" + URLEncoder.encode(certType);
        query += "&subjectName=" + URLEncoder.encode(subjectName);
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("checkDN");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);

    }

    private String normalize(String s) {

        String val = "";

        for (int i = 0; i < s.length(); i++) {
            if ((s.charAt(i) == '\\') && (s.charAt(i + 1) == 'n')) {
                i++;
                continue;
            } else if ((s.charAt(i) == '\\') && (s.charAt(i + 1) == 'r')) {
                i++;
                continue;
            } else if (s.charAt(i) == '"') {
                continue;
            }
            val += s.charAt(i);
        }
        return val;
    }

    private String pkcs7Convertcert(String s) {

        String val = "";

        int len = s.length();

        for (int i = 0; i < len; i = i + 64) {

            if (i + 64 < len) {
                val = val + s.substring(i, i + 64) + "\n";
            } else {
                val = val + s.substring(i, len);
            }

        }
        return val;
    }

    private boolean certRequest(boolean trustM) {
        // This function prepares a Certificate Request.
        // Submits it to the CA
        // Approves the request.
        // And then installs it

        System.out.println("configuring Cert Instance :  cert Request");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);

        String query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&certType=" + URLEncoder.encode(certType);
        query += "&subjectName=" + URLEncoder.encode(subjectName);
        query += "&keyType=" + URLEncoder.encode(keyType);
        query += "&keyLength=" + URLEncoder.encode(keyLength);
        query += "&tokenName=" + URLEncoder.encode(CERTtokenName);

        if (subca) {
            query += "&sslCABit=true";
            query += "&objectSigningCABit=true";
            query += "&wirelessSupport=false";
            query += "&mailCABit=true";
            query += "&isCA=true";
            query += "&ski=true";
            query += "&aki=true";
            query += "&keyUsage=true";
            query += "&caSigningCertReqFormat=PKCS10";
        }

        if (subsystems.equals("ra")) {
            query += "&aki=" + URLEncoder.encode(aki);
            query += "&keyUsage=" + URLEncoder.encode("true");
            query += "&signing_cert=" + signingCert;
        }

        if (certType.equals("serverCert")) {
            query += "&sslServerBit=" + URLEncoder.encode("true");
            query += "&sslClientBit=" + URLEncoder.encode("true");
            query += "&serverCertReqFormat=PKCS10";
        } else {
            if (subsystems.equals("ra")) {
                query += "&sslClientBit=" + URLEncoder.encode("true");
                query += "&raSigningCertReqFormat=PKCS10";
            }

            if (subsystems.equals("ocsp")) {
                query += "&ocspSigningCertReqFormat=PKCS10";
            }

            if (subsystems.equals("kra")) {
                // added keyUsage
                query += "&keyUsage=" + URLEncoder.encode("true");
                // added URLEncoder
                query += "&aki=" + URLEncoder.encode(aki);
                query += "&kraTransportCertReqFormat=PKCS10";
            }
        }

        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("certRequest");
        query += "&caHostname=" + caHostname;
        query += "&caEEPort=" + caEEPort;
        query += "&cmsSeed=0";

        setPostQueryString(query);
        if (!Connect(myStringUrl)) {
            System.out.println("Error :certRequest");
            return false;
        }

        String res = spage.toString();

        certRequestStr = res.substring(
                res.indexOf("certReq: ") + "certReq: ".length(),
                res.indexOf("-----END NEW CERTIFICATE REQUEST-----"));
        certRequestStr += "-----END NEW CERTIFICATE REQUEST-----";

        int ReqId = 0;

        UserEnroll e = new UserEnroll(caHostname, caEEPort, subjectName, "test",
                "test", null, "test", "test", cdir, tokenpwd, ssl_clientcert,
                keyLength, keyType, null, null, signingCert);

        e.setpkcs10Request(certRequestStr);
        if (e.Enroll()) {
            ReqId = e.getRequestId();
        } else {
            System.out.println("Request was not successful");
            return false;
        }

        String trm;

        if (trustM) {
            trm = "true";
        } else {
            trm = "false";
        }

        Request r = new Request(caHostname, caAgentPortnum, CAadminId,
                CAadminPwd, CAcertnickname, cdir, tokenpwd, getString(ReqId),
                null, null, "approve", "enrollment", "showWaiting", null, trm);

        if (r.ApproveRequests(getString(ReqId)) <= -1) {
            System.out.println(
                    "Error : Agent request approval was not successful");
            return false;
        }

        System.out.println("configuring Cert Instance :  req Success");

        // Checking to see if request is approved.

        setConfigURL();
        myStringUrl = "http://" + host + ":" + adminPort + configURL;
        System.out.println(myStringUrl);

        query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);
        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&certType=" + URLEncoder.encode(certType);

        if (certType.equals("serverCert")) {
            query += "&serverCertReqID=" + ReqId;
        } else {
            query += "&raSigningCertReqID=" + ReqId;
        }

        query += "&serverRoot=" + URLEncoder.encode(serverRoot);
        query += "&caEEPort=" + caEEPort;
        query += "&caHostname=" + host;
        query += "&caEEType=https";
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("reqSuccess");
        query += "&cmsSeed=0";

        setPostQueryString(query);
        if (Connect(myStringUrl)) {

            checkRequest cr = new checkRequest(caHostname, caEEPort, cdir,
                    tokenpwd, getString(ReqId), null, null);

            if (cr.checkRequestStatus()) {
                String cert = cr.getpkcs7ChainCert();
                String certtmp = pkcs7Convertcert(cert);

                certtmp = normalize(certtmp);
                cert = "-----BEGIN CERTIFICATE-----" + "\n" + certtmp + "\n"
                        + "-----END CERTIFICATE-----\n";

                // install cert
                System.out.println(
                        "configuring Cert Instance :  install cert :" + cert);
                setConfigURL();
                myStringUrl = "http://" + host + ":" + adminPort + configURL;
                System.out.println(myStringUrl);
                query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);
                query += "&";
                query += "instanceID=" + URLEncoder.encode(instanceID);
                query += "&certType=" + URLEncoder.encode(certType);
                query += "&db.password=" + URLEncoder.encode(dbPassword);

                if (certType.equals("raSigningCert")) {
                    query += "&nickname="
                            + URLEncoder.encode(certType + " " + instanceID);
                    raSigningCert = "-----BEGIN CERTIFICATE-----" + "\n"
                            + cr.getCert() + "\n"
                            + "-----END CERTIFICATE-----\n";

                }

                if (certType.equals("kraTransportCert")) {
                    ComCrypto cCrypto = new ComCrypto();

                    kraTransportCert = cCrypto.normalize(cr.getCert());
                }

                if (certType.equals("serverCert")) {
                    query += "&nickname="
                            + URLEncoder.encode("Server-Cert" + " " + instanceID);
                }

                if (certType.equals("ocspSigningCert")) {
                    query += "&nickname="
                            + URLEncoder.encode(certType + " " + instanceID);
                }

                query += "&pkcs10=" + URLEncoder.encode(cert);
                query += "&opType=" + URLEncoder.encode("OP_MODIFY");
                query += "&taskID=" + URLEncoder.encode("installCert");
                query += "&cmsSeed=0";

                setPostQueryString(query);
                return (Connect(myStringUrl));
            }

        } else {
            System.out.println("Error: Request is not approved");
            return false;
        }
        return true;
    }

    private String getString(int m) {
        Integer x = new Integer(m);
        String s = x.toString();

        return s;
    }

    private boolean createCert() {
        System.out.println("configuring Cert Instance : Create Cert");

        // clauclate the validity dates for the cert.
        GregorianCalendar begin = new GregorianCalendar();
        GregorianCalendar end = new GregorianCalendar();
        Integer days = new Integer(certValidityDays);

        end.add(GregorianCalendar.DATE, days.intValue());

        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);

        String query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&serverRoot=" + URLEncoder.encode(serverRoot);
        query += "&db.password=" + URLEncoder.encode(dbPassword);
        query += "&subjectName=" + URLEncoder.encode(subjectName);
        query += "&certType=" + URLEncoder.encode(certType);

        query += "&beginYear="
                + URLEncoder.encode(getString(begin.get(GregorianCalendar.YEAR)));
        query += "&beginMonth="
                + URLEncoder.encode(
                        getString(begin.get(GregorianCalendar.MONTH)));
        query += "&beginDate="
                + URLEncoder.encode(getString(begin.get(GregorianCalendar.DATE)));
        query += "&beginHour="
                + URLEncoder.encode(getString(begin.get(GregorianCalendar.HOUR)));
        query += "&beginMin="
                + URLEncoder.encode(
                        getString(begin.get(GregorianCalendar.MINUTE)));
        query += "&beginSec="
                + URLEncoder.encode(
                        getString(begin.get(GregorianCalendar.SECOND)));

        query += "&afterYear="
                + URLEncoder.encode(getString(end.get(GregorianCalendar.YEAR)));
        query += "&afterMonth="
                + URLEncoder.encode(getString(end.get(GregorianCalendar.MONTH)));
        query += "&afterDate="
                + URLEncoder.encode(getString(end.get(GregorianCalendar.DATE)));
        query += "&afterHour="
                + URLEncoder.encode(getString(end.get(GregorianCalendar.HOUR)));
        query += "&afterMin="
                + URLEncoder.encode(getString(end.get(GregorianCalendar.MINUTE)));
        query += "&afterSec="
                + URLEncoder.encode(getString(end.get(GregorianCalendar.SECOND)));

        query += "&keyType=" + URLEncoder.encode(keyType);
        query += "&keyLength=" + URLEncoder.encode(keyLength);

        query += "&certLen=" + URLEncoder.encode("-1");
        query += "&tokenName=" + URLEncoder.encode(CERTtokenName);
        query += "&aki=" + URLEncoder.encode(aki);
        query += "&keyUsage=" + URLEncoder.encode("true");

        if (certType.equals("serverCert")) {
            query += "&sslServerBit=" + URLEncoder.encode("true");
            query += "&sslClientBit=" + URLEncoder.encode("true");

        } else {
            query += "&caOComponent=" + URLEncoder.encode(caOComponent);
            query += "&caCComponent=" + URLEncoder.encode("us");

            query += "&isCA=" + URLEncoder.encode(isCA);
            query += "&ski=" + URLEncoder.encode(ski);
            query += "&tokenPasswd=" + URLEncoder.encode(tokenPWD);
            query += "&sslCABit=" + URLEncoder.encode(sslCABit);
            query += "&mailCABit=" + URLEncoder.encode(mailCABit);
            query += "&objectSigningCABit="
                    + URLEncoder.encode(objectSigningCABit);

        }
        query += "&hashType=" + URLEncoder.encode(hashType);

        query += "&sopPasswd=" + URLEncoder.encode(SingleSignOnPWD);
        query += "&wirelessSupport=" + URLEncoder.encode("false");
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("createCert");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);

    }

    private boolean singleSignON() {
        System.out.println("configuring Cert Instance : Single Signon");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String PWTags = "Internal:Internal LDAP Database:singlesignon";

        String query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&serverRoot=" + URLEncoder.encode(serverRoot);
        // query += "&singleSignonPwd=" + URLEncoder.encode(SingleSignOnPWD);
        query += "&singleSignonPWTags=" + URLEncoder.encode(PWTags);
        query += "&Internal=" + URLEncoder.encode(tokenPWD);
        query += "&Internal LDAP Database=" + URLEncoder.encode(dbPassword);
        query += "&pwcTokenname=" + URLEncoder.encode("internal");

        query += "&singlesignon=" + URLEncoder.encode(tokenPWD);

        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("singleSignon");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);

    }

    private boolean doMisc() {
        System.out.println("configuring Cert Instance : do Miscell");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String PWTags = "Internal:Internal LDAP Database:singlesignon";

        String query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&serverRoot=" + URLEncoder.encode(serverRoot);
        query += "&singleSignonPwd=" + URLEncoder.encode(SingleSignOnPWD);
        query += "&singleSignonPWTags=" + URLEncoder.encode(PWTags);
        query += "&Internal=" + URLEncoder.encode(tokenPWD);
        query += "&Internal LDAP Database=" + URLEncoder.encode(dbPassword);
        query += "&singlesignon=" + URLEncoder.encode(tokenPWD);
        query += "&deletePasswdConf=false";

        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("doMiscStuffs");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);
    }

    private boolean exitDeamon() {

        System.out.println("configuring Cert Instance : Exit Deamon");
        setDeamonURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&serverRoot=" + URLEncoder.encode(serverRoot);
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("exit");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);
    }

    private boolean ConfOCSP() {

        // Step 1. Start Deamon

        if (!startDeamon()) {
            System.out.println(
                    "Configuring Cert Instance: Unable to start deamon");
            return false;
        }

        // Sometimes it takes time to start deamon so wait for few seconds
        try {
            System.out.println("going to sleep for 10 seconds");
            Thread.sleep(10000);
        } catch (InterruptedException ie) {
            System.out.println("sleep exection");
        }

        // Step 1a: Initialize Token ( Changed in 6.0)jjj
        if (!initializePWD()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing pwd token");
            return false;
        }

        // Step 2. Configure Internal DB
        if (!configInternalDB()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring internal db");
            return false;
        }

        // Step 3. Create Admin Values
        if (!createAdminValues()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring admin values ");
            return false;
        }

        // Step 4. SubSystems

        if (!selectSubSystem()) {
            System.out.println(
                    "Configuring Cert Instance: error selecting subsystems");
            return false;
        }

        // Step 5. Network Configuration
        if (!networkConfig()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring network ports ");
            return false;
        }

        // Step 6: Initialize Token This has been moved to step 1a
        if (!initializeToken()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing token");
            return false;
        }

        // Step 7 : keyLenth
        if (!keyLength()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring KeyLength");
            return false;
        }

        // Step 8 : CheckDN
        if (!checkDN()) {
            System.out.println(
                    "Configuring Cert Instance: error checking deamon");
            return false;
        }

        // Step 9 : certRequest and Install  
        if (!certRequest(false)) {
            System.out.println("Configuring Cert Instance: error getting cert");
            return false;
        }

        // Create a SSL signing cert
        Date tmpdate = new Date();

        certType = "serverCert";
        subjectName = "CN=" + host + "." + adminDomain + ",OU=ssltest"
                + tmpdate.getTime() + ",O=SSL,C=US";
        keyLength = "512";
        keyType = "RSA";
        String mtokenPWD = tokenPWD;

        tokenPWD = "";
        ssl_clientcert = "false";
        signingCert = "server";

        if (!initializeToken()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing token");
            return false;
        }

        // Step 8 : keyLenth
        if (!keyLength()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring KeyLength");
            return false;
        }

        // Step 9 : CheckDN
        if (!checkDN()) {
            System.out.println(
                    "Configuring Cert Instance: error checking deamon");
            return false;
        }

        // Step 10 :
        if (!certRequest(false)) {
            System.out.println(
                    "Configuring Cert Instance: error creating Request");
            return false;
        }

        // After creating ssl cert
        tokenPWD = mtokenPWD;

        // Step 11
        if (!singleSignON()) {
            System.out.println(
                    "Configuring Cert Instance: error setting up singlesignon");
            return false;
        }

        // Step 11
        if (!doMisc()) {
            System.out.println(
                    "Configuring Cert Instance: error setting up miscell");
            return false;
        }

        // Step 12
        if (!exitDeamon()) {
            System.out.println(
                    "Configuring Cert Instance: Unable to exit deamon");
            return false;
        }

        return true;

    }

    private boolean setupStorageKey() {
        System.out.println("configuring Cert Instance :  Storage Key");
        setConfigURL();
        String myStringUrl = "http://" + host + ":" + adminPort + configURL;

        System.out.println(myStringUrl);
        String query = "AdminUserPassword=" + URLEncoder.encode(adminPWD);

        query += "&";
        query += "instanceID=" + URLEncoder.encode(instanceID);
        query += "&serverRoot=" + URLEncoder.encode(serverRoot);
        query += "&opType=" + URLEncoder.encode("OP_MODIFY");
        query += "&taskID=" + URLEncoder.encode("storageKey");
        query += "&tokenName=" + URLEncoder.encode("Internal");
        query += "&tokenPasswd=" + URLEncoder.encode("");
        query += "&keyLength=" + URLEncoder.encode("512");
        query += "&cmsSeed=0";
        setPostQueryString(query);
        return Connect(myStringUrl);
    }

    private boolean ConfRA() {
        // Start Configuring 

        // Step 1. Start Deamon

        if (!startDeamon()) {
            System.out.println(
                    "Configuring Cert Instance: Unable to start deamon");
            return false;
        }

        // Sometimes it takes time to start deamon so wait for few seconds
        try {
            System.out.println("going to sleep for 10 seconds");
            Thread.sleep(10000);
        } catch (InterruptedException ie) {
            System.out.println("sleep exection");
        }

        // Step 1a: Initialize Token ( Changed in 6.0)jjj
        if (!initializePWD()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing pwd token");
            return false;
        }

        // Step 2. Configure Internal DB
        if (!configInternalDB()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring internal db");
            return false;
        }

        // Step 3. Create Admin Values 
        if (!createAdminValues()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring admin values ");
            return false;
        }

        // Step 4. SubSystems 

        if (!selectSubSystem()) {
            System.out.println(
                    "Configuring Cert Instance: error selecting subsystems");
            return false;
        }

        // Step 5. Network Configuration
        if (!networkConfig()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring network ports ");
            return false;
        }

        // Step 6: Initialize Token This has been moved to step 1a
        if (!initializeToken()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing token");
            return false;
        }

        // Step 7 : keyLenth
        if (!keyLength()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring KeyLength");
            return false;
        }

        // Step 8 : CheckDN 
        if (!checkDN()) {
            System.out.println(
                    "Configuring Cert Instance: error checking deamon");
            return false;
        }

        // Step 9 : certRequest and Install  i.e approve the request as a trusted manager
        if (!certRequest(true)) {
            System.out.println("Configuring Cert Instance: error getting cert");
            return false;
        }

        // Create a SSL signing cert
        Date tmpdate = new Date();

        certType = "serverCert";
        subjectName = "CN=" + host + "." + adminDomain + ",OU=ssltest"
                + tmpdate.getTime() + ",O=SSL,C=US";
        keyLength = "512";
        keyType = "RSA";
        String mtokenPWD = tokenPWD;

        tokenPWD = "";
        ssl_clientcert = "false";
        signingCert = "server";

        if (!initializeToken()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing token");
            return false;
        }

        // Step 8 : keyLenth
        if (!keyLength()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring KeyLength");
            return false;
        }

        // Step 9 : CheckDN 
        if (!checkDN()) {
            System.out.println(
                    "Configuring Cert Instance: error checking deamon");
            return false;
        }

        // Step 10 :
        if (!certRequest(false)) {
            System.out.println(
                    "Configuring Cert Instance: error creating Request");
            return false;
        }

        // After creating ssl cert 
        tokenPWD = mtokenPWD;

        // Step 11 
        if (!singleSignON()) {
            System.out.println(
                    "Configuring Cert Instance: error setting up singlesignon");
            return false;
        }

        // Step 11 
        if (!doMisc()) {
            System.out.println(
                    "Configuring Cert Instance: error setting up miscell");
            return false;
        }

        // Step 12 
        if (!exitDeamon()) {
            System.out.println(
                    "Configuring Cert Instance: Unable to exit deamon");
            return false;
        }

        return true;
    }

    private boolean ConfKRA() {
        // Start Configuring 

        // Step 1. Start Deamon

        if (!startDeamon()) {
            System.out.println(
                    "Configuring Cert Instance: Unable to start deamon");
            return false;
        }

        // Sometimes it takes time to start deamon so wait for few seconds
        try {
            System.out.println("going to sleep for 10 seconds");
            Thread.sleep(10000);
        } catch (InterruptedException ie) {
            System.out.println("sleep exection");
        }

        // Step 1a: Initialize Token ( Changed in 6.0)jjj
        if (!initializePWD()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing pwd token");
            return false;
        }

        // Step 2. Configure Internal DB
        if (!configInternalDB()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring internal db");
            return false;
        }

        // Step 3. Create Admin Values 
        if (!createAdminValues()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring admin values ");
            return false;
        }

        // Step 4. SubSystems 

        if (!selectSubSystem()) {
            System.out.println(
                    "Configuring Cert Instance: error selecting subsystems");
            return false;
        }

        // Step 5. Network Configuration
        if (!networkConfig()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring network ports ");
            return false;
        }

        // Step 6: Initialize Token This has been moved to step 1a
        if (!initializeToken()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing token");
            return false;
        }

        // Step 7 : keyLenth
        if (!keyLength()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring KeyLength");
            return false;
        }

        // Step 8 : CheckDN 
        if (!checkDN()) {
            System.out.println(
                    "Configuring Cert Instance: error checking deamon");
            return false;
        }

        // Step 9 : certRequest and Install  i.e approve the request as a trusted manager
        if (!certRequest(true)) {
            System.out.println("Configuring Cert Instance: error getting cert");
            return false;
        }

        if (!setupStorageKey()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring storage key");
            return false;
        }

        // no need to do this from 7.1 due to new acl based key recovery
        /*
         if (!setupKRAAgents())
         { System.out.println("Configuring Cert Instance: error configuring storage key"); return false;}
         */

        // Create a SSL signing cert
        Date tmpdate = new Date();

        certType = "serverCert";
        subjectName = "CN=" + host + "." + adminDomain + ",OU=ssltest"
                + tmpdate.getTime() + ",O=SSL,C=US";
        keyLength = "512";
        keyType = "RSA";
        String mtokenPWD = tokenPWD;

        tokenPWD = "";
        ssl_clientcert = "false";
        signingCert = "server";

        if (!initializeToken()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing token");
            return false;
        }

        // Step 8 : keyLenth
        if (!keyLength()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring KeyLength");
            return false;
        }

        // Step 9 : CheckDN 
        if (!checkDN()) {
            System.out.println(
                    "Configuring Cert Instance: error checking deamon");
            return false;
        }

        // Step 10 :
        if (!certRequest(false)) {
            System.out.println(
                    "Configuring Cert Instance: error creating Request");
            return false;
        }

        // After creating ssl cert 
        tokenPWD = mtokenPWD;

        // Step 11 
        if (!singleSignON()) {
            System.out.println(
                    "Configuring Cert Instance: error setting up singlesignon");
            return false;
        }

        // Step 11 
        if (!doMisc()) {
            System.out.println(
                    "Configuring Cert Instance: error setting up miscell");
            return false;
        }

        // Step 12 
        if (!exitDeamon()) {
            System.out.println(
                    "Configuring Cert Instance: Unable to exit deamon");
            return false;
        }

        return true;
    }

    // /// Sub CA configuration

    private boolean ConfSubCA() {
        // Start Configuring

        // Step 1. Start Deamon

        if (!startDeamon()) {
            System.out.println(
                    "Configuring Cert Instance: Unable to start deamon");
            return false;
        }

        // Sometimes it takes time to start deamon so wait for few seconds
        try {
            System.out.println("going to sleep for 10 seconds");
            Thread.sleep(10000);
        } catch (InterruptedException ie) {
            System.out.println("sleep exection");
        }

        // Step 1a: Initialize Token ( Changed in 6.0)jjj
        if (!initializePWD()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing pwd token");
            return false;
        }

        // Step 2. Configure Internal DB
        if (!configInternalDB()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring internal db");
            return false;
        }

        // Step 3. Create Admin Values
        if (!createAdminValues()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring admin values ");
            return false;
        }

        // Step 4. SubSystems

        if (!selectSubSystem()) {
            System.out.println(
                    "Configuring Cert Instance: error selecting subsystems");
            return false;
        }

        // Step 5. Network Configuration
        if (!networkConfig()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring network ports ");
            return false;
        }

        // Step 6: Initialize Token This has been moved to step 1a
        if (!initializeToken()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing token");
            return false;
        }

        // Step 7 : keyLenth
        if (!keyLength()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring KeyLength");
            return false;
        }

        // Step 8 : CheckDN
        if (!checkDN()) {
            System.out.println(
                    "Configuring Cert Instance: error checking deamon");
            return false;
        }

        // Step 9 : certRequest and Install  i.e approve the request as a trusted manager
        if (!certRequest(false)) {
            System.out.println("Configuring Cert Instance: error getting cert");
            return false;
        }

        // Create a SSL signing cert
        Date tmpdate = new Date();

        certType = "serverCert";
        subjectName = "CN=" + host + "." + adminDomain + ",OU=ssltest"
                + tmpdate.getTime() + ",O=SSL,C=US";
        keyLength = "512";
        keyType = "RSA";
        String mtokenPWD = tokenPWD;

        tokenPWD = "";
        ssl_clientcert = "false";
        signingCert = "server";

        if (!initializeToken()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing token");
            return false;
        }

        // Step 8 : keyLenth
        if (!keyLength()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring KeyLength");
            return false;
        }

        // Step 9 : CheckDN
        if (!checkDN()) {
            System.out.println(
                    "Configuring Cert Instance: error checking deamon");
            return false;
        }

        // Step 10 :
        if (!certRequest(false)) {
            System.out.println(
                    "Configuring Cert Instance: error creating Request");
            return false;
        }

        // After creating ssl cert
        tokenPWD = mtokenPWD;

        // Step 11
        if (!singleSignON()) {
            System.out.println(
                    "Configuring Cert Instance: error setting up singlesignon");
            return false;
        }

        // Step 11
        if (!doMisc()) {
            System.out.println(
                    "Configuring Cert Instance: error setting up miscell");
            return false;
        }

        // Step 12
        if (!exitDeamon()) {
            System.out.println(
                    "Configuring Cert Instance: Unable to exit deamon");
            return false;
        }

        return true;
    }

    // / CA

    // org
    private boolean ConfCA() {
        // Start Configuring 

        // Step 1. Start Deamon

        if (!startDeamon()) {
            System.out.println(
                    "Configuring Cert Instance: Unable to start deamon");
            return false;
        }

        // Sometimes it takes time to start deamon so wait for few seconds
        try {
            System.out.println("going to sleep for 10 seconds");
            Thread.sleep(10000);
        } catch (InterruptedException ie) {
            System.out.println("sleep exection");
        }

        // Step 1a: Initialize Token ( Changed in 6.0)jjj
        if (!initializePWD()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing pwd token");
            return false;
        }

        // Step 2. Configure Internal DB
        if (!configInternalDB()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring internal db");
            return false;
        }

        // Step 3. Create Admin Values 
        if (!createAdminValues()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring admin values ");
            return false;
        }

        // Step 4. SubSystems 

        if (!selectSubSystem()) {
            System.out.println(
                    "Configuring Cert Instance: error selecting subsystems");
            return false;
        }

        // SetSerial Number 
        if (!setSerial("1", "1000000")) {
            System.out.println(
                    "Configuring Cert Instance: error setting serial number");
            return false;
        }

        if (!setOCSP()) {
            System.out.println(
                    "Configuring Cert Instance: error selecting subsystems");
            return false;
        }

        // Step 5. Network Configuration
        if (!networkConfig()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring network ports ");
            return false;
        }

        // Step 6. setting up Server Migration 

        // if (!serverMigration())
        // { System.out.println("Configuring Cert Instance: error configuring server migration"); return false;}

        // Step 7: Initialize Token
        if (!initializeToken()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing token");
            return false;
        }

        // Step 8 : keyLenth
        if (!keyLength()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring KeyLength");
            return false;
        }

        // Step 9 : CheckDN 
        if (!checkDN()) {
            System.out.println(
                    "Configuring Cert Instance: error checking deamon");
            return false;
        }

        // Step 10 :
        if (!createCert()) {
            System.out.println("Configuring Cert Instance: error creating cert");
            return false;
        }

        // Create a SSL signing cert
        Date tmpdate = new Date();

        certType = "serverCert";
        subjectName = "CN=" + host + "." + adminDomain + ",OU=ssltest"
                + tmpdate.getTime() + ",O=SSL,C=US";
        keyType = "RSA";
        keyLength = "512";
        String mtokenPWD = tokenPWD;

        tokenPWD = "";

        if (!initializeToken()) {
            System.out.println(
                    "Configuring Cert Instance: error initializing token");
            return false;
        }

        // Step 8 : keyLenth
        if (!keyLength()) {
            System.out.println(
                    "Configuring Cert Instance: error configuring KeyLength");
            return false;
        }

        // Step 9 : CheckDN 
        if (!checkDN()) {
            System.out.println(
                    "Configuring Cert Instance: error checking deamon");
            return false;
        }

        // Step 10 :
        if (!createCert()) {
            System.out.println("Configuring Cert Instance: error creating cert");
            return false;
        }

        // After creating ssl cert 
        tokenPWD = mtokenPWD;

        // Step 11 
        if (!singleSignON()) {
            System.out.println(
                    "Configuring Cert Instance: error setting up singlesignon");
            return false;
        }

        // Step 11 
        if (!doMisc()) {
            System.out.println(
                    "Configuring Cert Instance: error setting up miscell");
            return false;
        }

        // Step 12 
        if (!exitDeamon()) {
            System.out.println(
                    "Configuring Cert Instance: Unable to exit deamon");
            return false;
        }

        return true;
    }

    // Configure Clone 

    public boolean readProperties() {
        // Read the properties file and assign values to variables .
        try {
            getProperties(propFileName);
        } catch (Exception e) {
            System.out.println(
                    "exception reading Properties File " + e.getMessage());
        }

        // read all properties 

        adminDomain = props.getProperty("inst.admin.domain");
        adminID = props.getProperty("inst.admin.uid");
        adminPWD = props.getProperty("inst.admin.pwd");
        adminPort = props.getProperty("inst.admin.port");
        machineName = props.getProperty("inst.machineName");
        host = props.getProperty("inst.host");
        serverID = props.getProperty("inst.serverIdentifier");
        instanceID = "cert-" + serverID;
        serverRoot = props.getProperty("inst.serverRoot");
        // Just for debugging"
        sieURL = props.getProperty("inst.sie.url");
        dbConnPort = props.getProperty("inst.dbConnPort");
        dbConnHost = props.getProperty("inst.dbConnHost");
        dbInstanceName = props.getProperty("inst.dbInstanceName");
        dbPassword = props.getProperty("inst.dbPassword");
        dbLDAPauthDN = props.getProperty("inst.ldap.auth.dn");
        dbmode = props.getProperty("inst.dbmode");
        ldapServerDB = props.getProperty("inst.ldapServerDB");
        certAdminName = props.getProperty("inst.cert.admin.name");
        certAdminUid = props.getProperty("inst.cert.admin.uid");
        certAdminPWD = props.getProperty("inst.cert.admin.pwd");
        kra = props.getProperty("inst.subsystem.kra");
        subsystems = props.getProperty("inst.subsystem");
        ca = props.getProperty("inst.subsystem.ca");
        ra = props.getProperty("inst.subsystem.ra");
        ocsp = props.getProperty("inst.subsystem.ocsp");
        remoteKRA = props.getProperty("inst.subsystem.remoteKRA");
        wirelessSupport = props.getProperty("inst.subsystem.wireless");
        eeHttpPort = props.getProperty("inst.ee.http.port");
        eeHttpsPort = props.getProperty("inst.ee.https.port");
        agentHttpsPort = props.getProperty("inst.agent.https.port");
        radminHttpsPort = props.getProperty("inst.admin.https.port");
        tokenName = props.getProperty("inst.tokenName");
        tokenPWD = props.getProperty("inst.token.pwd");
        signingCert = props.getProperty("inst.cert.Type");
        certType = signingCert;
        keyType = props.getProperty("inst.key.type");
        keyLength = props.getProperty("inst.key.length");
        SingleSignOnPWD = props.getProperty("inst.singlesignon.pwd");
        subjectName = props.getProperty("inst.ca.dn");
        isCA = props.getProperty("inst.isca");
        aki = props.getProperty("inst.aki");
        ski = props.getProperty("inst.ski");
        sslCABit = props.getProperty("inst.sslCABit");
        objectSigningCABit = props.getProperty("inst.objectSigningCABit");
        mailCABit = props.getProperty("inst.mailCABit");
        hashType = props.getProperty("inst.hash.Type");
        caOComponent = props.getProperty("inst.ca.component");
        certValidityDays = props.getProperty("inst.cert.validity");
        caHostname = props.getProperty("inst.cahostname");
        caPortnum = props.getProperty("inst.caportnum");
        caAgentPortnum = props.getProperty("inst.caASport");
        caTimeout = props.getProperty("inst.catimeout");
        caEEPort = props.getProperty("inst.caEEport");
        cloneInstanceId = props.getProperty("inst.cloneid");
        CAadminId = props.getProperty("inst.caAdminId");
        CAadminPwd = props.getProperty("inst.caAdminPwd");
        CAcertnickname = props.getProperty("inst.caCertnickname");
        enpropfile = props.getProperty("inst.propfile");
        cdir = props.getProperty("inst.certdir");
        tokenpwd = props.getProperty("inst.certtokenpwd");

        if (subsystems.equals("ca")) {
            return ConfCA();
        }
        if (subsystems.equals("ra")) {
            return ConfRA();
        }
        if (subsystems.equals("ocsp")) {
            return ConfOCSP();
        }
        if (subsystems.equals("kra")) {
            return ConfKRA();
        }
        if (subsystems.equals("subca")) {
            subca = true;
            subsystems = "ca";
            return ConfSubCA();
        }

        return true;
    } // end of r

    public static void main(String args[]) {
        // Exit Status - (-1) for error
        // - 1  Configured and server Alive
        // - 0  Configured bur could not sart server 

        AutoInstaller t = new AutoInstaller();

        System.out.println(args.length);
        t.setPropFile(args[0]);

        if (args.length < 1) {
            System.out.println("Usage : PropertiesFilePath");
            System.exit(-1);
        }

        System.out.println("configuring Cert Instance : Start");

        boolean st = t.readProperties();

        if (st) {
            System.out.println("Configuring Cert Instance : Successful");
            System.exit(1);
        } else {

            System.out.println("Configuring Cert Instance : Error ");
            System.exit(0);
        }
    }

} // end of class 

