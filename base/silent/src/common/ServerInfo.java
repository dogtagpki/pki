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

import java.net.*;
import java.io.*;
import java.util.*;


/**
 * CMS Test framework .
 * This class fetches all the necssary ServerInformation to run the test . For example AdminServer information linke port , hsotname, Config LDAP server port, CMS servers Agentport,AdminPort, EESSL port, EE port etc..
 */


public class ServerInfo {

    public String serverRoot, instanceRoot, instanceID;
    public String ldapPort, ldapHost, ldapSSLPort, ldapBaseSuffix, adminPort, admDN, admDNPW, singleSignOnPWD, domain;
    public String caSigningCertNickName, raSigningCertNickName, ocspSigningCertNickName, kraTransportCertNickName;
    public String ServerCertNickName, CertAuthority;
    public String CMSAgentPort, CMSEESSLPort, CMSEEPort, CMSAdminPort, IDBPort;

    public static CMSProperties props = null;
    public static CMSProperties CMSprops = null;

    // Private variables 
    private int i;
    public String CMSConfigFile, AdminConfigFile;

    public ServerInfo() {}

    /**
     * Constructor. Takes Server root as parameter for example ( /export/qa). Reads and collects information about adminserver and Config LDAP server.
     */
    public ServerInfo(String sroot) {
        serverRoot = sroot;
        AdminConfigFile = serverRoot + "/admin-serv/config/adm.conf";
        readAdminConfig();
        SystemInfo();
    }

    /**
     * Constructor. Takes Serverroot ( /export/qa) and instanceRoot (/export/qa/cert-jupiter2) as parameters . Reads and collects information about Admin Server , Config LDAP server and CMS server .
     */


    public ServerInfo(String sroot, String instRoot) {
        serverRoot = sroot;
        instanceRoot = instRoot;
        CMSConfigFile = instanceRoot + "/config/CS.cfg";
        AdminConfigFile = serverRoot + "/admin-serv/config/adm.conf";
        instanceID = instanceRoot.substring(instanceRoot.indexOf("cert-") + 5);
        readAdminConfig();
        SystemInfo();
        parseServerXML();
        readCMSConfig();
    }

    public String GetAdminPort() {
        return adminPort;
    }

    public String GetConfigLDAPPort() {
        return ldapPort;
    }

    public String GetHostName() { 
        if (domain.indexOf(".") > 0) {
            return domain.substring(0, domain.indexOf("."));
        } else { 
            return domain;
        }
    }

    public String GetInstanceID() {
        return instanceID;
    }

    public String GetCMSConfigFileName() {
        return CMSConfigFile;
    }

    public String GetDomainName() { 
        return ldapHost.substring(ldapHost.indexOf(".") + 1); 
    }

    public String GetAgentPort() {
        return CMSAgentPort;
    }

    public String GetEESSLPort() {
        return CMSEESSLPort;
    }

    public String GetEEPort() {
        return CMSEEPort;
    }

    public String GetCMSAdminPort() {
        return CMSAdminPort;
    }

    public String GetInternalDBPort() {
        return IDBPort;
    }

    public String GetCertAuthority() {
        return CertAuthority;
    }

    public String GetCASigningCert() {
        return caSigningCertNickName;
    }

    public String GetRASigningCert() {
        return raSigningCertNickName;
    }

    public String GetServerCertNickName() {
        return ServerCertNickName;
    }

    public void setInstanceRoot(String instRoot) {
        instanceRoot = instRoot;
        CMSConfigFile = instanceRoot + "/config/CS.cfg";
        AdminConfigFile = serverRoot + "/admin-serv/config/adm.conf";
        instanceID = instanceRoot.substring(instanceRoot.indexOf("cert-") + 5);
        SystemInfo();
        parseServerXML();
        readCMSConfig();
    }

    // Private functions 
    private void SystemInfo() {
        try {
            domain = InetAddress.getLocalHost().getHostName(); 
            System.out.println("Debu:SystemInfo " + domain);
        } catch (Exception e) {
            System.out.println("Exception InetAddress : " + e.getMessage());
        }
 
    }

    private void parseServerXML() {
        int AGENT = 1;
        int ADMIN = 2;
        int EE_SSL = 3;
        int EE_NON_SSL = 4;
        int IP = 5;
        int PORT = 6; 
        BufferedReader in = null;

        try {
            String xmlFilePath = instanceRoot + "/config/server.xml";

            in = new BufferedReader(new FileReader(xmlFilePath));
            String s = in.readLine();

            while (s != null) {
                // <SSLPARAMS servercertnickname="Server-Cert cert-firefly"
                int index = s.indexOf("servercertnickname");

                if (index >= 0) {
                    String str = s.substring(index + 20);
                    StringTokenizer tokenizer = new StringTokenizer(str, "\"");

                    if (tokenizer.hasMoreElements()) {
                        String mServerCertNickname = tokenizer.nextToken();
                    }
                }

                // <LS id="agent" ip="0.0.0.0" port="8101" security="on"
                // acceptorthreads="1" blocking="no">
                if (s.startsWith("<LS id=")) {
                    StringTokenizer st = new StringTokenizer(s, "\"");
                    int index1 = 5, index2 = 3;

                    while (st.hasMoreTokens()) {
                        String token = st.nextToken();

                        if (token.equalsIgnoreCase("agent")) {
                            index1 = AGENT;
                        } else if (token.equalsIgnoreCase("admin")) {
                            index1 = ADMIN;
                        } else if (token.equalsIgnoreCase("eeSSL")) {
                            index1 = EE_SSL;
                        } else if (token.equalsIgnoreCase("ee_nonSSL")) {
                            index1 = EE_NON_SSL;
                        } else if (token.equals(" ip=")) {
                            index2 = IP;
                        } else if (token.equals(" port=")) {
                            index2 = PORT;
                        }
                        
                        if (index1 != 5 && index2 == IP && !token.equals(" ip=")) {
                            String ip = token;
                        } else if (index2 == PORT && !token.equals(" port=")) {
                            
                            switch (index1) {
                            case 1:
                                CMSAgentPort = token;
                                break;

                            case 2:
                                CMSAdminPort = token;
                                break;

                            case 3:
                                CMSEESSLPort = token;
                                break;

                            case 4:
                                CMSEEPort = token;
                                break;

                            default:
                                break; 

                            }

                            break;
                        }
                    } // while token
                } // if LS
                s = in.readLine();
            } // while file no end
            in.close();
        } catch (Exception e) {
            if (in != null) {
                try {
                    in.close();
                } catch (Exception ex) {}
            }
        }
    } 

    private void getProperties(String filePath) throws Exception {
        try {
            FileInputStream fis = new FileInputStream(filePath);

            props = new CMSProperties();
            props.load(fis);
            System.out.println("Reading Properties file successful");
            fis.close();
        } catch (Exception e) {
            System.out.println("exception " + e.getMessage());
        }

    }

    private String stripSpace(String s) {

        String val = "";

        for (int i = 0; i < s.length(); i++) {
            if ((s.charAt(i) == ' ')) {
                i++;
                continue;
            } else {  
                val += s.charAt(i);
            }
        }
        return val;
    }

    private void readAdminConfig() {
        String ldapHostStr = "ldapHost:";
        String ldapPortStr = "ldapPort:";
        String adminPortStr = "port:";

        try {
            FileInputStream fis = new FileInputStream(AdminConfigFile);
            int size = fis.available();
            byte b[] = new byte[size];

            if (fis.read(b) != b.length) {
                System.out.println("Could not read ");

            } else {  
                String tmpstr = new String(b, 0, b.length);
                int ret;

                if ((ret = tmpstr.indexOf(ldapHostStr)) > -1) {
                    ldapHost = tmpstr.substring(ret + ldapHostStr.length() + 1,
                            tmpstr.indexOf("ldapPort", ret) - 1);
                    ldapHost = stripSpace(ldapHost);
                    // System.out.println(ldapPort);
                }

                if ((ret = tmpstr.indexOf(ldapPortStr)) > -1) {
                    ldapPort = tmpstr.substring(ret + ldapPortStr.length() + 1,
                            tmpstr.indexOf("sie", ret) - 1);
                    ldapPort = stripSpace(ldapPort);
                    // System.out.println(ldapPort);
                }
                if ((ret = tmpstr.indexOf(adminPortStr)) > -1) {
                    adminPort = tmpstr.substring(ret + adminPortStr.length() + 1,
                            tmpstr.indexOf("ldapStart", ret) - 1);
                    adminPort = stripSpace(adminPort);
                    // System.out.println(adminPort);
                }

            }
 
            fis.close();
        } catch (Exception e) {
            System.out.println("exception " + e.getMessage());
        }

    }

    private void readCMSConfig() {

        try {
            FileInputStream fis = new FileInputStream(CMSConfigFile);

            CMSprops = new CMSProperties();
            CMSprops.load(fis);
            System.out.println("Reading CMS Config file successful");
            CertAuthority = CMSprops.getProperty("subsystem.0.id");
            if (CertAuthority.equals("ca")) {
                caSigningCertNickName = CMSprops.getProperty(
                        "ca.signing.cacertnickname");
                ServerCertNickName = "Server-Cert cert-" + instanceID;
            }
            if (CertAuthority.equals("ra")) {
                raSigningCertNickName = CMSprops.getProperty(
                        "ra.signing.cacertnickname");
                ServerCertNickName = "Server-Cert cert-" + instanceID;
            }
            IDBPort = CMSprops.getProperty("internaldb.ldapconn.port");
        	
            fis.close();
        } catch (Exception e) {
            System.out.println("exception " + e.getMessage());
        }

    }

    public static void main(String args[]) {
        ServerInfo s = new ServerInfo("Test", "Test");

        System.out.println(" Admin Port : " + s.GetAdminPort());
        System.out.println(" LDAP Port : " + s.GetConfigLDAPPort());
        System.out.println("Hostname " + s.GetHostName());
        System.out.println("InstanceID" + s.GetInstanceID());   
        System.out.println(" doamin name : " + s.GetDomainName()); 
        System.out.println("AgentPort " + s.GetAgentPort());
        System.out.println("EESSLPort " + s.GetEESSLPort());
        System.out.println("EEPort " + s.GetEEPort());
        System.out.println("CMSAdminPort :" + s.GetCMSAdminPort()); 
        System.out.println("CAAuthority : " + s.GetCertAuthority());
        System.out.println("CASigningCert:" + s.GetCASigningCert());
        System.out.println("RASigningCert:" + s.GetRASigningCert());
        System.out.println("ServerCert" + s.GetServerCertNickName());
 
    }// end of function main

} // end of class 

