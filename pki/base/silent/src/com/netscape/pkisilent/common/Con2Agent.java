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

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Enumeration;
import java.util.Vector;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.AlreadyInitializedException;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11Token;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLClientCertificateSelectionCallback;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.util.Password;

/**
 * CMS Test framework .
 * Submits a requests to agent port with sslclient authentication.
 */

public class Con2Agent implements SSLClientCertificateSelectionCallback,
        SSLCertificateApprovalCallback {

    private int i, port;
    private String host, certdir, certnickname, tokenpwd, certname, query;
    private String ACTIONURL;

    private BufferedReader stdin = null;
    private StringBuffer stdout = new StringBuffer();

    public Con2Agent() {
    }

    /**
     * Constructor. Takes hostname , portnumber , certificate nickname, token password ,client certdb directory
     * 
     * @param hostname
     * @param portnumber
     * @param agent cert nickname
     * @param token password
     * @param certdb directory
     */

    public Con2Agent(String hs, int p, String cname, String tpwd, String cdir) {
        host = hs;
        port = p;
        certnickname = cname;
        tokenpwd = tpwd;
        certdir = cdir;
    }

    public boolean approve(X509Certificate x509, SSLCertificateApprovalCallback.ValidityStatus status) {
        return true;
    }

    public String select(@SuppressWarnings("rawtypes") Vector nicknames) {
        Enumeration<?> e = nicknames.elements();

        System.out.println("nicknames size = " + nicknames.size());
        int i = 0;

        while (e.hasMoreElements()) {
            String s = (String) e.nextElement();

            i++;
        }

        if (i > 0) {
            return (String) nicknames.elementAt(0);
        } else {
            return null;
        }

    }

    // Get and Set methods 

    /*
     * Get the page returned by the server 
     */

    public StringBuffer getPage() {
        return stdout;
    }

    /*
     * Set the query string to be submitted to the server 
     */

    public void setQueryString(String qu) {
        query = qu;
    }

    /*
     *Set token password 
     */

    public void setTokenPassword(String pwd) {
        tokenpwd = pwd;
    }

    /*
     * Set Client cert database
     */

    public void setCertDBDir(String cdir) {
        certdir = cdir;
    }

    /*
     * Set host name
     */

    public void setHost(String hs) {
        host = hs;
    }

    /*
     * set Agent port number 
     */

    public void setPort(int p) {
        port = p;
    }

    /*
     * Set Agent cert nickname 
     */

    public void setCertNickName(String cname) {
        certnickname = cname;
    }

    /*
     * Set action URL 
     */

    public void setActionURL(String url) {
        ACTIONURL = url;
    }

    // Submit requests 

    public boolean Send() {
        boolean st = false;

        try {

            if (!loginCertDB()) {
                return false;
            }

            SSLSocket socket = new SSLSocket(host, port, null, 0, this, null);

            System.out.println("Con2Agent.java: host = " + host);
            System.out.println("Con2Agent.java: port = " + port);
            System.out.println("Con2Agent.java: certnickname = " + certnickname);

            socket.setClientCertNickname(certnickname);
            System.out.println("Connected to the socket");

            OutputStream rawos = socket.getOutputStream();
            BufferedOutputStream os = new BufferedOutputStream(rawos);
            PrintStream ps = new PrintStream(os);

            System.out.println(ACTIONURL);
            System.out.println("Query :" + query);
            ps.println("POST " + ACTIONURL + " HTTP/1.0");
            ps.println("Connection: Keep-Alive");
            ps.println("Content-type: application/x-www-form-urlencoded");
            ps.println("Content-length: " + query.length());
            ps.println("");
            ps.println(query);
            ps.println("\r");
            ps.flush();
            os.flush();
            BufferedReader stdin1 = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            String line;

            while ((line = stdin1.readLine()) != null) {
                stdout.append(line + "\n");
                System.out.println(line);
            }

            // Send Connection: close to let the server close the connection. 
            // Else the socket on the server side continues to remain in TIME_WAIT state

            ps.println("Connection: close");
            ps.flush();
            os.flush();
            os.close();
            rawos.close();
            ps.close();
            stdin1.close();
            socket.close();

            if (socket.isClosed()) {
                System.out.println("Con2Agent.java : Socket is Closed");
            } else {
                System.out.println("Con2Agent.java : Socket not Closed");
            }

        } catch (Exception e) {
            System.out.println("some exception: in Send routine" + e);
            return false;
        }

        return true;

    }

    private boolean loginCertDB() {
        CryptoManager manager;
        Password pass1 = null, pass2 = null;

        try {
            System.out.println("Step 1: Initializing CryptoManager");
            CryptoManager.initialize(certdir);

            System.out.println("Step 2: Login to Cert Database");
            manager = CryptoManager.getInstance();
            CryptoToken token = (PK11Token) manager.getInternalKeyStorageToken();

            if (token.isLoggedIn()) {
                System.out.println("Con2Agent: Logged in incorrect");
            }

            System.out.println("tokenpwd:" + tokenpwd);
            char[] passchar1 = new char[tokenpwd.length()];

            tokenpwd.getChars(0, tokenpwd.length(), passchar1, 0);

            pass1 = new Password((char[]) passchar1.clone());
            token.login(pass1);

            X509Certificate cert2 = manager.findCertByNickname(certnickname);

            certname = cert2.getNickname();
            return true;

        } catch (AlreadyInitializedException e) {
            System.out.println("Crypto manager already initialized");
            return true;
        } catch (NumberFormatException e) {
            System.err.println("Invalid key size: " + e);
            return false;
        } catch (java.security.InvalidParameterException e) {
            System.err.println("Invalid key size: " + e);
            return false;

        } catch (Exception e) {
            System.err.println("some exception:" + e);
            e.printStackTrace();
            return false;
        }

    }

    public boolean Send_withGET() {

        boolean st = false;

        try {

            if (!loginCertDB()) {
                return false;
            }

            SSLSocket socket = new SSLSocket(host, port, null, 0, this, null);

            socket.setClientCertNickname(certnickname);
            System.out.println("Connected to the socket");

            OutputStream rawos = socket.getOutputStream();
            BufferedOutputStream os = new BufferedOutputStream(rawos);
            PrintStream ps = new PrintStream(os);

            System.out.println("Query in con2agent :" + query);
            System.out.println("ACTIONURL in con2agent : " + ACTIONURL);

            ps.println("GET " + ACTIONURL + query + " HTTP/1.0");
            ps.println("");
            ps.println("\r");
            ps.flush();
            os.flush();
            BufferedReader stdin2 = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            String line;

            while ((line = stdin2.readLine()) != null) {
                stdout.append(line + "\n");
            }
            stdin2.close();

            socket.close();

        } catch (Exception e) {
            System.err.println("some exception: in Send routine" + e);
            return false;
        }

        return true;

    }

} // end of class 
