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


public class createinstance {

    private static String host;
    private static String port;
    private static String AdminDN;
    private static String AdminDNPW;
    private static String serverRoot;
    private static String instanceID;
    private static String sieurl;
    private static String adminDomain;
    private static String first_arg;

    public createinstance() {// do nothing :)
    }

    public void usage() {
        System.out.println("Usage : ");
        System.out.println("  createinstance -c host");
        System.out.println("                    port");
        System.out.println("                    AdminDN");
        System.out.println("                    AdminDNPW");
        System.out.println("                    adminDomain");
        System.out.println("                    serverRoot");
        System.out.println("                    instanceID");
        System.out.println("                    machineName");
        System.out.println("                    sieURL");
        System.out.println(" OR ");
        System.out.println(" createinstance -h <to print this usage string>");

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
        query += "&machineName=" + URLEncoder.encode(host + "." + adminDomain);

        PostQuery sm = new PostQuery(myStringUrl, AdminDN, AdminDNPW, query);

        return (sm.Send());

    }

    public static void main(String args[]) {
        createinstance newinstance = new createinstance();

        // set variables

        first_arg = args[0];
        if (args[0].equals("-h")) {
            newinstance.usage();
            System.exit(-1);
        } else if (args[0].equals("-c")) {
            host = args[1];
            port = args[2];
            AdminDN = args[3];
            AdminDNPW = args[4];
            serverRoot = args[5];
            instanceID = args[6];
            sieurl = args[7];
            adminDomain = args[8];

        }
	
        boolean st = newinstance.CreateInstance();

        if (!st) {
            System.out.println("ERROR: Certficate System - Instance NOT created");
            System.exit(-1);
        }

        System.out.println("Certficate System - Instance created");
        System.exit(0);
	
    }

}


;
