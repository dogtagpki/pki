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

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.ServerSocket;
import java.util.Properties;

import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

/**
 * CMS Test framework .
 * Before createing an instance of this class make sure you havae set an environment variable TEST_CONFIG_FILE.
 */

public class TestClient implements SSLCertificateApprovalCallback {

    public int port;

    // properties file parameters
    public static String host, ports, adminid, adminpwd, propfileName, cdir;
    public static String certnickname, keysize, keytype, tokenpwd;
    public static String serverRoot, instanceRoot, ldaprootDN, ldaprootDNPW, caInstanceRoot, dataDirectory;

    // Program variables
    public String STATUS;
    public Properties props = null;
    public String ACTION_STRING;
    public String query;
    public boolean debug = false;
    // Certificate nicknames to be used by Test Clients
    private String testConfigFile;

    public String caAgentCertName = "ca-agent";
    public String raAgentCertName = "ra-agent";
    public String ocspAgentCertName = "ocsp-agent";
    public String kraAgentCertName = "kra-agent";
    public String tksAgentCertName = "tks-agent";
    public String singleSignOnPWD = "secret12";
    public String adminCertName = "cn=admin";
    private String ldapBaseSuffix = "dc=netscape,dc=com";
    private String admDN = "admin";
    private String admDNPW = "admin";
    private String TmpDir;
    @SuppressWarnings("unused")
    private String TestLogFile;
    private String startupTests, cleanupTests;

    private X509Certificate SSLServerCert = null;

    // Cert Sub vart
    public String UID, OU, O, DN, E, CN, C, GN, SN, L, MAIL;
    // Enroll
    protected String PWD;
    // CRypto
    public ComCrypto cCrypt = new ComCrypto();
    public String pkcs10request = null;

    // Error

    public String ErrorDetail;

    private String serverKeyType, serverKeySize, serverKeyAlgo;

    private String unauth[] = {
            "Unauthorized Access", "Server Error",
            "Not Found", "Generic Unauthorized" };

    public boolean approve(X509Certificate x509, SSLCertificateApprovalCallback.ValidityStatus status) {
        SSLServerCert = x509;
        return true;
    }

    // Constructor

    public TestClient() {
        keysize = "1024";
        keytype = "RSA";
    }

    /**
     * Constructor . Takes the parameter for keysize and keytype .
     * Before creating a new instance of this class make sure you have set TEST_CONFIG_FILE variable in your
     * environnemt.
     * Reads the TEST_CONFIG_FILE . Initializes the certificate database. See engage.cfg file for example.
     *
     * @param keysize
     * @param keytype
     */

    public TestClient(String ks, String kt) {

        testConfigFile = ReadEnv("TEST_CONFIG_FILE");

        System.out.println(testConfigFile);
        readConfigFile();
        keysize = ks;
        keytype = kt;
        cCrypt.setCertDir(cdir);
        cCrypt.setCertnickname(adminCertName);
        cCrypt.setKeySize(keysize);
        cCrypt.setKeyType(keytype);
        cCrypt.setTokenPWD(tokenpwd);
        cCrypt.setDebug(true);
        cCrypt.CreateCertDB();

    }

    /**
     * Gets the SSLServer Certificate of the server
     */

    public X509Certificate getSSLServerCert() {
        return SSLServerCert;
    }

    /**
     * finds the cert with nickname cname in the clients cert database
     */

    public X509Certificate findCertByNickname(String cname) {

        return cCrypt.findCert(cname);

    }

    /**
     * Imports certificate to cert database.Takes parameters Certpackage and certnickname
     */
    boolean importCert(String cp, String nickname) {

        return cCrypt.importCert(cp, nickname);

    }

    /**
     * This function returns true if you choose to executeStartupTests
     */

    public boolean executeStartupTests() {

        if (startupTests == null) {
            return false;
        } else if (startupTests.equals("y")) {
            return true;
        } else {
            return false;
        }

    }

    /**
     * This function returns true if you choose to executeCleanupTests
     */

    public boolean executeCleanupTests() {

        if (cleanupTests == null) {
            return false;
        } else if (cleanupTests.equals("y")) {
            return true;
        } else {
            return false;
        }

    }

    public String GetServerRoot() {
        return serverRoot;
    }

    public String GetInstanceRoot() {
        return instanceRoot;
    }

    public String getErrorDetail() {
        return ErrorDetail;
    }

    public String GetAdminDN() {
        return admDN;
    }

    public String GetAdminDNPWD() {
        return admDNPW;
    }

    public String GetLDAPDN() {
        return ldaprootDN;
    }

    public String GetLDAPDNPW() {
        return ldaprootDNPW;
    }

    public String GetLDAPBASE() {
        return ldapBaseSuffix;
    }

    public String GetAdminCertName() {
        return adminCertName;
    }

    public String GetRAAgentCertName() {
        return raAgentCertName;
    }

    public String GetKRAAgentCertName() {
        return kraAgentCertName;
    }

    public String GetOCSPAgentCertName() {
        return ocspAgentCertName;
    }

    public String GetTKSAgentCertName() {
        return tksAgentCertName;
    }

    public String GetDataDirectory() {
        return dataDirectory;
    }

    public String GetClientCertDB() {
        return cdir;
    }

    public String GetClientCertDBPW() {
        return tokenpwd;
    }

    public String GetSingleSignOnPW() {
        return singleSignOnPWD;
    }

    public String GetCARoot() {
        return caInstanceRoot;
    }

    public String GetTmpDir() {
        return TmpDir;
    }

    public String GetServerKeySize() {
        return serverKeySize;
    }

    public String GetServerKeyType() {
        return serverKeyType;
    }

    public String GetServerKeyAlgorithm() {
        return serverKeyAlgo;
    }

    public void setStatusString(String ststr) {
        STATUS = ststr;
    }

    public void setDebug(boolean t) {
        debug = t;
    }

    public void setpkcs10Request(String t) {
        pkcs10request = t;
    }

    public void setHostName(String s) {
        host = s;
    }

    public void setCARoot(String s) {
        caInstanceRoot = s;
    }

    public void setTestLogFile(String s) {
        TestLogFile = s;
    }

    /**
     * parses a http page and returns true if any error is returned by server
     **/

    public boolean getError(String line) {

        int ret;

        ret = line.indexOf("fixed.errorDetails");

        if (line.indexOf("fixed.errorDetails") == 0) {
            ErrorDetail = line.substring(
                    ret + ("fixed.errorDetails = ").length());
            return true;
        }

        if (line.indexOf("fixed.errorDetails") >= 0) {
            ErrorDetail = line.substring(
                    ret + ("fixed.errorDetails = ").length());
            return true;
        }

        ret = line.indexOf("fixed.unexpectedError");

        if (line.indexOf("fixed.unexpectedError") == 0) {
            System.out.println("Processing unexpectedError");
            ErrorDetail = line.substring(
                    ret + ("fixed.unexpectedError = ").length());
            return true;
        }

        if (line.indexOf(unauth[0]) > 0) {
            ErrorDetail = unauth[0];
            return true;
        }
        if (line.indexOf(unauth[1]) > -1) {
            ErrorDetail = unauth[1];
            return true;
        }
        if (line.indexOf(unauth[2]) > -1) {
            ErrorDetail = unauth[2];
            return true;
        }
        if (line.indexOf(unauth[3]) > -1) {
            ErrorDetail = unauth[3];
            return true;
        }

        if (line.indexOf("errorReason") >= 0) {
            ErrorDetail = line.substring(ret + ("errorReason=").length());
            return true;
        }

        return false;
    }

    /**
     * Reads a properties file . Takes filename as input parameter.
     */

    public void getProperties(String fileName) throws Exception {
        try {
            FileInputStream fis = new FileInputStream(fileName);

            props = new Properties();
            props.load(fis);
        } catch (Exception e) {
            System.out.println("exception " + e.getMessage());
        }

    }

    public String ReadEnv(String str) {
        try {
            Process p = null;
            Runtime r = Runtime.getRuntime();
            String OS = System.getProperty("os.name").toLowerCase();

            if (OS.indexOf("windows") > 1) {
                p = r.exec("cmd.exe /c set");
            } else {
                p = r.exec("env");
            }

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(p.getInputStream()));
            String line;

            while ((line = br.readLine()) != null) {
                int idx = line.indexOf('=');
                String key = line.substring(0, idx);
                String value = line.substring(idx + 1);

                // System.out.println(key + "=" + value);
                if (key.startsWith(str)) {
                    return value;
                }
            }
            return null;
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return null;
    }

    private void readConfigFile() {
        try {
            getProperties(testConfigFile);
        } catch (Exception e) {
            System.out.println(
                    "exception reading TestConfigFile " + e.getMessage());
        }

        serverRoot = props.getProperty("SROOT");
        instanceRoot = props.getProperty("IROOT");
        dataDirectory = props.getProperty("DATA_DIR");
        ldapBaseSuffix = props.getProperty("LDAPBASESUFFIX");

        if (ldapBaseSuffix.indexOf("\"") > -1) {
            ldapBaseSuffix = ldapBaseSuffix.substring(1,
                    ldapBaseSuffix.length() - 1);
        }

        ldaprootDN = props.getProperty("LDAPROOTDN");
        // Strip of th e quotes "cn=directory manager" string
        if (ldaprootDN.indexOf("\"") > -1) {
            ldaprootDN = ldaprootDN.substring(1, ldaprootDN.length() - 1);
        }
        System.out.println("ldaprootDN : " + ldaprootDN);

        ldaprootDNPW = props.getProperty("LDAPROOTDNPW");
        cdir = props.getProperty("CERTDB");
        tokenpwd = props.getProperty("CERTDBPW");
        caInstanceRoot = props.getProperty("CAIROOT");
        admDN = props.getProperty("ADMINDN");
        admDNPW = props.getProperty("ADMINDNPW");
        singleSignOnPWD = props.getProperty("SINGLESIGNONPW");
        serverKeySize = props.getProperty("KEYSIZE");
        serverKeyType = props.getProperty("KEYTYPE");
        serverKeyAlgo = props.getProperty("KEYALGORITHM");

        TmpDir = props.getProperty("TMP_DIR");
        TestLogFile = props.getProperty("TEST_LOG_FILE");

        String de = props.getProperty("DEBUG");

        if (de == null) {
            debug = false;
        } else if (de.equals("true")) {
            debug = true;
        } else {
            debug = false;
        }

    }

    /**
     * returns a String representation of an interger
     */
    public String getString(int m) {
        Integer x = new Integer(m);
        String s = x.toString();

        return s;
    }

    /**
     * returns FreePort in this machine . Takes a parmater portnumber. For example getFreePort("4026").
     */
    public String getFreePort(String s) {
        Integer x = new Integer(s);
        int p = x.intValue();

        // if p = 0, then the serversocket constructor get a free port by itself
        p = 0;
        try {
            ServerSocket ss1 = new ServerSocket(p);

            p = ss1.getLocalPort();
            System.out.println("Obtained Free Port = " + p);
            ss1.close();
            return (getString(p));
        } catch (Exception e) {
            System.out.println("Unable to get Free Port");
            e.printStackTrace();
            p = 0;
            return (getString(p));
        }

        // This following method doesn't Always get a free port.
        // while (st) {
        // if(isSocketUnused(host,p) )
        // st=false;
        // p++;
        // }
        // return (getString(p));

    }

    /**
     * Reads a file and returns the cert request as string
     **/

    public String readRequest(String filename) {
        try {
            FileInputStream f1 = new FileInputStream(filename);
            int size = f1.available();
            byte b[] = new byte[size];

            if (f1.read(b) != b.length) {
                return null;
            }

            f1.close();
            String s = new String(b);

            return s;
        } catch (Exception e) {
            System.out.println("exception " + e.getMessage());
            return null;
        }
    }

    public static void main(String args[]) {
        TestClient t = new TestClient("1024", "RSA");

        /*
         *******************************************************************
         *  Sample programs to initialze calsses
         *******************************************************************
         */

        /*
         ********************************************************************
         * To Test AutoInstaller
         *******************************************************************
         */

        /*
         AutoInstaller a = new AutoInstaller(t.GetServerRoot());

         ServerInfo s = new ServerInfo(t.GetServerRoot());
         System.out.println (" Admin Port : " + s.GetAdminPort());
         System.out.println (" LDAP Port : "+ s.GetConfigLDAPPort());
         System.out.println( "Hostname " + s.GetHostName());
         System.out.println(" doamin name : " + s.GetDomainName());

         t.setHostName(s.GetHostName());
         // Set adminServer Info
         a.setAdminInfo(s.GetHostName(),s.GetAdminPort(),s.GetDomainName(),"admin","admin");
         a.setAdminInfo(s.GetHostName(),s.GetAdminPort(),"mcom.com","admin","admin");

         // setCAInfo
         a.setCAInfo(s.GetHostName(),"1027","8100","admin","secret12");
         //setInternalDB info
         String dp = t.getFreePort("38900");
         a.setInternalDBInfo(s.GetHostName(),"38907","ca-db","cn=directory manager","secret12"  );

         // set tokenInfo

         a.setTokenInfo("Internal","secret12");

         // set Subsystem info
         String agp = t.getFreePort("8100");
         String adp = t.getFreePort("8200");
         String eesp = t.getFreePort("1027");
         String eep = t.getFreePort("1100");

         System.out.println(agp);

         a.setSubSystemInfo("testra",t.GetServerRoot(),"RSA","1024","MD5","365","cn=certificate manager,ou=test,o=test",adp,agp,eesp,eep);

         a.setClientDBInfo(t.GetClientCertDB(),"secret12",t.GetAdminCertName());

         a.ConfigureCA("admin","admin","secret12","secret12");

         // a.ConfigureRA("admin","admin","secret12","secret12");

         */

        /*
         ******************************************************
         *   Example to Get Server Details
         ******************************************************
         */

        ServerInfo s = new ServerInfo(t.GetServerRoot(), t.GetInstanceRoot());

        t.setHostName(s.GetHostName());

        System.out.println("AgentPort " + s.GetAgentPort());
        System.out.println("EESSLPort " + s.GetEESSLPort());
        System.out.println("EEPort " + s.GetEEPort());
        System.out.println("CMSAdminPort :" + s.GetCMSAdminPort());
        System.out.println("IDBPort : " + s.GetInternalDBPort());
        System.out.println("CAAuthority : " + s.GetCertAuthority());
        System.out.println("CASigningCert:" + s.GetCASigningCert());
        System.out.println("RASigningCert:" + s.GetRASigningCert());
        System.out.println("ServerCert" + s.GetServerCertNickName());
        System.out.println("------------------------------------------");
        System.out.println(" Internal Database Test:");
        System.out.println(" LDAP Port : " + s.GetConfigLDAPPort());
        System.out.println("Hostname " + s.GetHostName());

        DirEnroll de = new DirEnroll(s.GetHostName(), s.GetEESSLPort());

        de.setAuthenticator("Portal");
        de.setUIDInfo("caeetest110", "secret12");
        de.enroll();

        /* ****************************************************************
         * CMC Enroll
         ***************************************************************
         */

        /* CMSUtils cmsutils = new CMSUtils(t.GetServerRoot());
         String requestfile="/u/lgopal/work/tetCMS/ns/tetframework/testcases/CMS/6.0/acceptance/data/basic/cmcreq/cmctest1.req";
         cmsutils.runCMCEnroll(t.GetClientCertDB(),"cn=admin",t.GetClientCertDBPW(),requestfile);
         Profiles pr = new Profiles(s.GetHostName(),s.GetEESSLPort());
         pr.setProfileType("caCMCUserCert");
         pr.setCertAuthority("ca");

         String request = t.readRequest(requestfile+".out");
         String bstr = "-----BEGIN NEW CERTIFICATE REQUEST-----";
         String estr="-----END NEW CERTIFICATE REQUEST-----";
         String  Blob1 = request.substring(bstr.length() + 1);
         String Blob2 = Blob1.substring(0,Blob1.indexOf(estr));
         request=Blob2;


         pr.setRequest(request);

         pr.setUserInfo("UID=test1,Ou=netscape,o=aol","test","test","test","netscape","aol");
         pr.clientCertEnroll();
         */

        /* ****************************************************************
         * OCSP Client stuff
         ************************************************************
         */

        /*
         String ip= "10.169.25.26";
         OCSPClient ocspclient= new  OCSPClient(s.GetHostName(),ip,s.GetEEPort(),t.GetClientCertDB(),t.GetClientCertDBPW(),"cn=admin" ,"/tmp/ocsp.out","4");
         ocspclient.setCert(t.findCertByNickname("ocsp-agent"));

         ocspclient.SendOCSPRequest();
         */

        /*
         *****************************************************
         * Test CRMFcleint and KRA REcovery and Archival
         *****************************************************
         */

        /*
         *********************************************************
         * OCSP Agent stuff
         *********************************************************
         */

        /* Retrieval rtr = new Retrieval(s.GetHostName(),s.GetEESSLPort());
         rtr.getCACert();
         System.out.println("CA Cert chain" + rtr.getCert());

         OcspAgent ocspAgent= new OcspAgent(s.GetHostName(),"8111");
         ocspAgent.setAgentCertName(t.GetOCSPAgentCertName());

         String cert = "-----BEGIN CERTIFICATE-----"+"\n"+rtr.getCert()+"\n"+"-----END CERTIFICATE-----\n";

         ocspAgent.setCACert(cert);
         ocspAgent.addCA();
         */

        /*
         ***************************************************************
         Submit Profile based request
         *********************************************************
         */

        /*
         Profiles pr = new Profiles(s.GetHostName(),s.GetEESSLPort());
         pr.setProfileType("caUserCert");
         //		pr.setProfileType("caDirUserCert");

         pr.setCertAuthority("ca");
         pr.setUserInfo("UID=test1,Ou=netscape,o=aol","test","test","test","netscape","aol");
         //pr.setDirUserInfo("test","netscape");
         pr.clientCertEnroll();
         System.out.println("Request ID is " + pr.getRequestID());


         Request re = new Request (s.GetHostName(),s.GetAgentPort(),"ca");
         re.setAgentCertName(t.GetAdminCertName());
         re.ApproveProfileRequests(pr.getRequestID());
         */

        /*
         String TransportCert="MIICJTCCAY6gAwIBAgIBBTANBgkqhkiG9w0BAQQFADBDMRswGQYDVQQKExJhY2NlcHRhY25ldGVzdDEwMjQxFzAVBgNVBAsTDmFjY2VwdGFuY2V0ZXN0MQswCQYDVQQDEwJjYTAeFw0wMzA0MjMyMTM3NTFaFw0wNDA0MjIwOTMzMzFaMDkxETAPBgNVBAoTCHRlc3QxMDI0MRcwFQYDVQQLEw5hY2NlcHRhbmNldGVzdDELMAkGA1UEAxMCcmEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANVW81T7GatHIB25kF0jdY4h4hOF1NAlAHE2YdN/UEyXuU22CfwrIltA3x/6sKFHhbbFysn6nGJlgKipPJqJDwyYTIv07hgoXqgcUu8fSYQg4BDHYhpHJxsUt3BSfADTjxAUHize7C2F8TVhBIcWW043FSkwvAiUjJb7uqQRKn7lAgMBAAGjMzAxMA4GA1UdDwEB/wQEAwIFIDAfBgNVHSMEGDAWgBTqvc3UPGDSWq+21DZGSUABNGIUbDANBgkqhkiG9w0BAQQFAAOBgQCNLJivNDHTTmCb2vDefUwLMxXNjuHwrbjVqymHPFqUjredTq2Yp+Ed1zxj+mxRovzegd65Tbnx+MV84j8K3Qc1kWOC+kbohAY9svSPsN3o5Q5BB19+5nUPC5Gk/mxkWJWWJLOnpKJGiAHMZIr58TH7hF8KQWXWMN9ikSFkPj0a/g==";


         CRMFClient CrmfClient = new CRMFClient(s.GetHostName(),s.GetEEPort());
         CrmfClient.setDBInfo(t.GetClientCertDB(),t.GetClientCertDBPW());
         CrmfClient.setTransportCert(TransportCert);
         CrmfClient.setUserInfo("user","netscape");
         CrmfClient.setLDAPInfo(t.GetLDAPDN(),t.GetLDAPDNPW());
         CrmfClient.setDualKey(true);

         if(!CrmfClient.Enroll())
         {System.out.println("CRMFClient : could not submit  request");}


         checkRequest cr = new checkRequest(s.GetHostName(),s.GetEESSLPort(),t.getString(CrmfClient.getRequestId()),"false");
         cr.checkRequestStatus();
         System.out.println("Serial num " + cr.getSerialNumber());
         System.out.println("cert pack " + cr.getCert());

         KraAgent kraAgent = new KraAgent(s.GetHostName(),"8111");
         kraAgent.setAgentCertName("cn=admin");
         System.out.println("KRAAgent List archival");

         Vector aReq= kraAgent.ListArchivalRequests();
         int i=0;
         while(i < aReq.size() )
         {
         System.out.print(aReq.elementAt(i) + " ");
         i++;
         }

         kraAgent.setCertificate(cr.getCert());
         kraAgent.setLocalAgent(false);
         kraAgent.recoverKeys();
         */

        /*
         *************************************************************
         *   Example to Connect oto Config Directory port
         *************************************************************
         */

        /*
         CMSLDAP cmsldap = new CMSLDAP(s.GetHostName(),s.GetConfigLDAPPort(),t.GetLDAPDN(),t.GetLDAPDNPW());
         if(cmsldap.connect())
         System.out.println("LDAP Connection successful");
         else
         System.out.println("Error Connecting to LDAPSERVER");

         // Add user to config directoory
         if (cmsldap.userAdd("ou=people,"+t.GetLDAPBASE(),"t2","t2","t2","netscape"))
         System.out.println("Added user to Config directory");

         */

        /*
         *************************************************************
         *   Example to Submit a CRMFCleint request to CA
         *************************************************************
         */

        /*
         String TransportCert =
                "MIICJTCCAY6gAwIBAgIBBTANBgkqhkiG9w0BAQQFADBDMRswGQYDVQQKExJhY2NlcHRhY25ldGVzdDEwMjQxFzAVBgNVBAsTDmFjY2VwdGFuY2V0ZXN0MQswCQYDVQQDEwJjYTAeFw0wMzA0MTgyMjMwMDhaFw0wNDA0MTcxMDI2MDhaMDkxETAPBgNVBAoTCHRlc3QxMDI0MRcwFQYDVQQLEw5hY2NlcHRhbmNldGVzdDELMAkGA1UEAxMCcmEwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN6sQ3mSU8mL6i6gTZIXDLzOZPhYOkQLpnJjit5hcPZ0JMn0CQVXo4QjKN1xvuZv8qVlZoQw9czmzp/knTa0sCDgFKd0r+u0TnLeZkJMSimgFnma9CnChlaDHnBd8Beu4vyaHmo7rJ0xA4etn7HjhmKbaQZOcv/aP0SW9JXRga7ZAgMBAAGjMzAxMA4GA1UdDwEB/wQEAwIFIDAfBgNVHSMEGDAWgBSC3fsQHb7fddr2vL0UdkM2dAmUWzANBgkqhkiG9w0BAQQFAAOBgQBkAGbgd9HIqwoLKAr+V6bj9oWesDmDH80gPPxj10qyWSQYIs8PofOs/75yGS9nxhydtgSMFoBgCPdroUI31kZQQlFzxtudGoKD+5MWSXho79XzPwpjheOBYgpX6ch+L4tMLFDpqeraB1yZESO5EEeKm20DGVBOKVWxHhddO1BenA==";

         CRMFClient	CrmfClient = new CRMFClient(s.GetHostName(),s.GetEEPort());
         CrmfClient.setDBInfo(t.GetClientCertDB(),t.GetClientCertDBPW());
         CrmfClient.setTransportCert(TransportCert);
         CrmfClient.setUserInfo("user","netscape");
         CrmfClient.setLDAPInfo(t.GetLDAPDN(),t.GetLDAPDNPW());
         CrmfClient.setDualKey(true);

         if(!CrmfClient.Enroll())
         {System.out.println("CRMFClient : could not submit  request");}
         */

        /* KRA Agent list archived request */

        /* ServerInfo KRAsvrInfo = new ServerInfo(t.GetServerRoot());
         String KRAinstanceRoot=t.GetServerRoot() + "/cert-" + "KRARSA1024" ;
         KRAsvrInfo.setInstanceRoot(KRAinstanceRoot);*/

        /* System.out.println("KRAAgent ");
         KraAgent kraAgent = new KraAgent(s.GetHostName(),s.GetAgentPort());
         kraAgent.setAgentCertName(t.GetKRAAgentCertName());
         System.out.println("KRAAgent List archival");

         Vector aReq= kraAgent.ListArchivalRequests();
         int i=0;
         while(i < aReq.size() )
         {
         System.out.print(aReq.elementAt(i) + " ");
         i++;
         }

         */

        // cmsldap.disconnect();

        /*
         *************************************************************
         *   Example to submit manual user enrollment request
         *************************************************************
         /*


         /*
         UserEnroll ue = new UserEnroll(s.GetHostName(),"1029");
         ue.setUserInfo("E=testman,CN=testman,OU=netscape,O=aol,UID=testman1,C=US","testman", "testman", "testman1", "netscape","t");

         boolean flag = ue.clientCertEnroll();
         if(flag)
         System.out.println("Success submitted request");
         */

        /*
         *************************************************************
         *   Example to submit   Directory based enroolemt request
         *************************************************************
         /*

         /*
         // Add user to config directoory
         if (cmsldap.userAdd("dc=netscape,dc=com","t2","t2","t2","netscape"))
         System.out.println("Success ");

         if(cmsldap.TurnOnSSL("slapd-jupiter2","Server-Cert cert-jupiter2","7000"))
         System.out.println("Turned on ssl");
         else
         return;

         cmsldap.TurnOffSSL();

         cmsldap.disconnect();

         DirEnroll de = new DirEnroll(s.GetHostName(),s.GetEESSLPort());
         de.setUIDInfo("t2","netscape");
         de.enroll();

         */

        /*
         *************************************************************
         *   Example to submit Admin Enrollment request
         *************************************************************
         /*

         /*

         AdminEnroll ade = new AdminEnroll("jupiter2","8200","cn=CMS Administrator,UID=admin,C=US","admin", "secret12");
         flag = ade.Enroll();
         if (flag)
         System.out.println("adminEnrolled Successfully");
         */

        /*
         *************************************************************
         *   Example   gent List Pending request
         *************************************************************
         /*

         /*

         // Agent List and Approve Request
         Request re = new Request (s.GetHostName(),s.GetAgentPort(),s.GetCertAuthority());
         re.setAgentCertName(t.GetAdminCertName());
         re.ListPendingRequests("2","70");
         re.ApproveRequests(t.getString(ue.getRequestId()));
         */

        /*
         *************************************************************
         *   Example for CheckRequest Status and add the certificate to internal db
         *************************************************************
         /*

         /*
         // check request status and Revoke cert
         checkRequest cr = new checkRequest(s.GetHostName(),s.GetEESSLPort(),t.getString(ue.getRequestId()),"false");
         checkRequest cr = new checkRequest(s.GetHostName(),s.GetEESSLPort(),"1","false");

         cr.checkRequestStatus();
         System.out.println("Serial num " + cr.getSerialNumber());
         System.out.println("cert pack " + cr.getCert());

         String st= "-----BEGIN CERTIFICATE-----"+"\n"+cr.getCert()+"\n"+"-----END CERTIFICATE-----\n";
         System.out.println("cert pack " + st);

         cmsldap.getXCertificate(st.getBytes());

         */

        /*
         *************************************************************
         *   Example  agent ro revoke request
         *************************************************************
         /*

         /*
         Revoke rr = new Revoke (s.GetHostName(),s.GetAgentPort(),s.GetCertAuthority(),t.getString(cr.getSerialNumber()));
         rr.revokeCerts();
         */

        /*
         *************************************************************
         *   Example   Agent update CRL
         *************************************************************
         /*

         /*
         // Update CRLand DISPLAY it

         System.out.println("Displayin CRL");
         CRL crl = new CRL (s.GetHostName(),s.GetAgentPort(),"/tmp/crlfile");
         crl.setAgentCertName(t.GetAdminCertName());
         crl.updateCRL();
         crl.displayCRL();
         crl.getRevokedCerts();
         */

        // Update CRL in Directory
        /* UpdateDir dcrl = new UpdateDir(s.GetHostName(),s.GetEESSLPort());
         dcrl.updateDir();*/

        /*
         *************************************************************
         *   Example for stopping and starting servers
         *************************************************************
         */

        /*
         DSTask idb = new DSTask(t.GetServerRoot()+"/slapd-jupiter2-db");
         if (idb.ldapStop()) System.out.println("IDB stopped");
         if(idb.ldapStart()) System.out.println("IDB Started");

         System.out.println("------------------------------------------");
         System.out.println(" CMS Test:");
         CMSTask task = new CMSTask(t.GetInstanceRoot());
         task.CMSStop();
         task.CMSStart();
         */

    }// end of function main

}
