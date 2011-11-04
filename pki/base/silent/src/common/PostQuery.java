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
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import com.netscape.osutil.OSUtil;

/**
 * CMS Test framework .
 * This class submits request to admin server after authenticating with UID and Password. You can get back the response by calling the method. getPage().
 */



public class PostQuery {

    private boolean st;
    private String NmcStatus = "NMC_STATUS: 0";
    private String postQuery = null;
    private String adminID, adminPWD, URLString;

    private StringBuffer stdout = new StringBuffer();

    /**
     * Constructor . Takes the parameters urlstring("http://hostname:<portnumber> , Id for authenticating to the server, password for authentication to the server and query which needs to be submitted to the server 
     */

    public PostQuery(String urlstr, String authid, String authpwd, String querystring) {   

        URLString = urlstr;
        adminID = authid;
        adminPWD = authpwd;
        postQuery = querystring;

    }

    public void setNMCStatus(String m) {
        NmcStatus = m;
    }

    public void setPostQueryString(String querystring) {
        postQuery = querystring;
    }

    public void setAuth(String ID, String Pwd) {
        adminID = ID;
        adminPWD = Pwd;
    }

    public StringBuffer getPage() {
        return stdout;
    }

    public boolean Send() {
        // / This functions connects to the URL and POST HTTP Request . 
        // It compares with NMC_STATUS  and return the status.
        System.out.println(URLString);
        st = false;

        try {

            BufferedReader mbufferedReader = null; 
            URL myUrl = new URL(URLString);
            String userPassword = adminID + ":" + adminPWD;

            System.out.println("adminid=" + adminID);
            System.out.println("adminpwd=" + adminPWD);
            // String encoding = new sun.misc.BASE64Encoder().encode(
            //         userPassword.getBytes());
            String encoding = OSUtil.BtoA(
                    userPassword.getBytes());
            HttpURLConnection URLCon = (HttpURLConnection) myUrl.openConnection();

            URLCon.setRequestProperty("Authorization", "Basic " + encoding);
            URLCon.setDoOutput(true);
            URLCon.setDoInput(true);
            URLCon.setUseCaches(false);
            URLCon.setRequestProperty("Content-type",
                    "application/x-www-form-urlencoded");
            // URLCon.setRequestMethod("POST");
            System.out.println("After post");

            DataOutputStream os = new DataOutputStream(URLCon.getOutputStream()); 

            System.out.println("Query: " + postQuery);

            int querylength = postQuery.length();

            os.writeBytes(postQuery);
            os.flush();
            os.close();
        
            InputStream Content = (InputStream) URLCon.getInputStream();

            System.out.println("Configuring Cert Instance : Return Response");
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(Content));
            String line;

            while ((line = in.readLine()) != null) {
                System.out.println(line);
                stdout.append(line + "\n");
                st = line.startsWith(NmcStatus);
                if (st) {
                    break;
                }
            } 
            URLCon.disconnect();
        } // try 
        catch (MalformedURLException e) {
            System.out.println(URLString + " is not a valid URL.");
	
        } catch (IOException e) {
            System.out.println("exception : " + e.getMessage());
        }
        System.out.println(st);
        return st;
    }

}
