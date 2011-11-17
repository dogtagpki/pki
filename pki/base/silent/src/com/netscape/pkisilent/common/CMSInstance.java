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
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URLEncoder;


public class CMSInstance {

    private int i;
    private boolean st;
    private String host, port, AdminDN, AdminDNPW, serverRoot, instanceID, sieurl, adminDomain, machineName;

    /**
     * CMS Test framework .
     * This class Creates and Removes a CMS server instance 
     */


    /**
     * Constructor. Takes parameters hostname, adminserverport, adminDN, adminDNpassword, Dominanname, ServerRoot( full path) , instanceID, mnameand sieURL. mname is the fully qualified name of the server ( jupiter2.nscp.aoltw.net) sieURL is ("ldap://jupiter2.nscp.aoltw.net:(ConfigLADPPort)/o=NetscapeRoot"
     */

    private String cs_server_root, cs_tps_root, tps_hostname, tps_fqdn, tps_instanceid, tps_ee_port, tps_agent_port, tps_auth_ldap_host, tps_auth_ldap_port, tps_auth_ldap_suffix, ca_hostname, ca_ee_port, tks_hostname, tks_agent_port, token_db_hostname, token_db_port, token_db_suffix, token_db_passwd;

    public CMSInstance(String h, String p, String AdDN, String pwd, String domain, String sroot, String insID, String mname, String sieURL) {

        host = h;
        port = p;
        AdminDN = AdDN;
        AdminDNPW = pwd;
        adminDomain = domain;
        serverRoot = sroot;
        machineName = mname;
        instanceID = insID;
        sieurl = sieURL;
    }

    public CMSInstance(String croot,
            String troot,
            String th,
            String tfqdn,
            String tid,
            String tep,
            String tagp,
            String tldaphost,
            String tldapport,
            String tldapsuffix,
            String ch,
            String ceep,
            String tkh,
            String tkagp,
            String toh,
            String toagp,
            String tosuffix,
            String topasswd) {

        cs_server_root = croot;
        cs_tps_root = troot;
        tps_hostname = th;
        tps_fqdn = tfqdn;
        tps_instanceid = tid;
        tps_ee_port = tep;
        tps_agent_port = tagp;
        tps_auth_ldap_host = tldaphost;
        tps_auth_ldap_port = tldapport;
        tps_auth_ldap_suffix = tldapsuffix;
        ca_hostname = ch;
        ca_ee_port = ceep;
        tks_hostname = tkh;
        tks_agent_port = tkagp;
        token_db_hostname = toh;
        token_db_port = toagp;
        token_db_suffix = tosuffix;
        token_db_passwd = topasswd;

    }

    public boolean CreateTPSInstance() throws IOException {
        // steps
        // 1. create .cfg file
        // 2. run create.pl with that .cfg file
	
        FileOutputStream out = new FileOutputStream(
                cs_server_root + "/tps_auto_config.cfg");
        BufferedWriter awriter;

        awriter = new BufferedWriter(new OutputStreamWriter(out, "8859_1"));
        awriter.write("CS_SERVER_ROOT=" + cs_server_root);
        awriter.newLine();
        awriter.write("CS_TPS_ROOT=" + cs_tps_root);
        awriter.newLine();
        awriter.write("TPS_HOSTNAME=" + tps_hostname);
        awriter.newLine();
        awriter.write("TPS_FQDN=" + tps_fqdn);
        awriter.newLine();
        awriter.write("TPS_INSTANCEID=" + tps_instanceid);
        awriter.newLine();
        awriter.write("TPS_EE_PORT=" + tps_ee_port);
        awriter.newLine();
        awriter.write("TPS_AGENT_PORT=" + tps_agent_port);
        awriter.newLine();
        awriter.write("TPS_AUTH_LDAP_HOST=" + tps_auth_ldap_host);
        awriter.newLine();
        awriter.write("TPS_AUTH_LDAP_PORT=" + tps_auth_ldap_port);
        awriter.newLine();
        awriter.write("TPS_AUTH_LDAP_SUFFIX=" + tps_auth_ldap_suffix);
        awriter.newLine();
        awriter.write("CA_HOSTNAME=" + ca_hostname);
        awriter.newLine();
        awriter.write("CA_EE_PORT=" + ca_ee_port);
        awriter.newLine();
        awriter.write("TKS_HOSTNAME=" + tks_hostname);
        awriter.newLine();
        awriter.write("TKS_AGENT_PORT=" + tks_agent_port);
        awriter.newLine();
        awriter.write("TOKEN_DB_HOSTNAME=" + token_db_hostname);
        awriter.newLine();
        awriter.write("TOKEN_DB_PORT=" + token_db_port);
        awriter.newLine();
        awriter.write("TOKEN_DB_SUFFIX=" + token_db_suffix);
        awriter.newLine();
        awriter.write("TOKEN_DB_PASSWD=" + token_db_passwd);
        awriter.newLine();

        awriter.flush();
        out.close();

        try {
            Process p = null;
            Runtime r = Runtime.getRuntime();
            // String[] se = {"perl", cs_server_root+"/bin/cert/tps/setup/create.pl" , "-i", cs_server_root+"/tps_auto_config.cfg" };
            String[] se = {
                "perl",
                "/home/ckannan/cms/src/ns/netkeyra/setup/create.pl", "-i",
                cs_server_root + "/tps_auto_config.cfg" };

            System.out.println(se);
            p = r.exec(se);  
            p.waitFor();
            String line;

            if (p.exitValue() == 0) {
                BufferedReader br = new BufferedReader(
                        new InputStreamReader(p.getInputStream()));

                while ((line = br.readLine()) != null) {
                    System.out.println(line);
                }
            } else {
                BufferedReader br = new BufferedReader(
                        new InputStreamReader(p.getErrorStream()));

                while ((line = br.readLine()) != null) {
                    System.out.println(line);
                }
            }
        } catch (Throwable e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
            return false;
        }

        return true;
    }

    public boolean CreateInstance() {

        String startURL = "/cert/Tasks/Operation/Create";
        String myStringUrl = "http://" + host + "." + adminDomain + ":" + port
                + startURL;

        System.out.println(myStringUrl);
	
        String query = "serverRoot=" + URLEncoder.encode(serverRoot);

        query += "&instanceID=" + URLEncoder.encode(instanceID);
        query += "&adminDomain=" + URLEncoder.encode(adminDomain);
        query += "&sieURL=" + URLEncoder.encode(sieurl);
        query += "&adminUID=" + URLEncoder.encode(AdminDN);
        query += "&adminPWD=" + URLEncoder.encode(AdminDNPW);
        query += "&machineName=" + URLEncoder.encode(machineName);

        PostQuery sm = new PostQuery(myStringUrl, AdminDN, AdminDNPW, query);

        return (sm.Send());
   
    }

    public boolean RemoveInstance() {

        String startURL = "/cert-" + instanceID + "/Tasks/Operation/Remove";
        String myStringUrl = "http://" + host + ":" + port + startURL;

        System.out.println(myStringUrl);
	
        String query = "serverRoot=" + URLEncoder.encode(serverRoot);

        query += "&instanceID=" + URLEncoder.encode(instanceID);
	
        PostQuery sm = new PostQuery(myStringUrl, AdminDN, AdminDNPW, query);

        st = sm.Send();

        if (st) {
            System.out.println("Removed the cert instance");
        } else {
            System.out.println("Could not remove the cert instance");
        }

        startURL = "/slapd-" + instanceID + "-db" + "/Tasks/Operation/Remove";
        myStringUrl = "http://" + host + ":" + port + startURL;

        System.out.println(myStringUrl);
	
        query = "serverRoot=" + URLEncoder.encode(serverRoot);
        query += "&InstanceName=" + URLEncoder.encode(instanceID + "-db");
	
        PostQuery rmdb = new PostQuery(myStringUrl, AdminDN, AdminDNPW, query);

        rmdb.setNMCStatus("NMC_Status: 0");
        return (rmdb.Send());
   
    }

    public static void main(String args[]) {
        // Exit Status - (-1) for error

        // Exit Status - (-1) for error
        // - 0 FAIL
        // - 1 PASS
 
        boolean st;
  
        System.out.println(args.length);
        if (args.length < 10) {
            System.out.println(
                    "Usage : <task:Create/REmove> host port AdminDN AdminDNPW adminDomain serverRoot instanceID machineName sieURL");
            System.exit(-1);
        }   

        int task = 0;

        args[0] = args[0].toLowerCase();
        if (args[0].equals("create")) { 
            task = 0;
        }
        if (args[0].equals("remove")) {
            task = 1;
        }
   
        CMSInstance t = new CMSInstance(args[1], args[2], args[3], args[4],
                args[5], args[6], args[7], args[8], args[9]);

        switch (task) {
        
        case 0:
            st = t.CreateInstance();
            if (st) { 
                System.out.println("server Instance created ");
                System.exit(1);
            } else {
	
                System.out.println("Error: Server Instance could not be created");
                System.exit(0);
            }
            break;

        case 1:
            st = t.RemoveInstance();
            if (st) { 
                System.out.println("Server instance removed");
                System.exit(1);
            } else {
	
                System.out.println("Server instance could not be removed");
                System.exit(0);
            }
            break;

        default:
            System.out.println("Incorrect usage");
            System.exit(-1);

        } // end of switch
    }// end of function main

} // end of class 

