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
import java.net.URLEncoder;
import java.util.Date;
import java.util.GregorianCalendar;

import org.mozilla.jss.ssl.SSLSocket;



/**
 * CMS Test framework - Legacyenrollment forms for Directory based enrollmnet  and Portal based enrollment .
 * Certificate issuance through Legacy Directory based enrollment and Portal based enrollment form. 
 *<P>
 */


public class DirEnroll extends TestClient {

    private int i;
    private String Authenticator = "UserDir";
    private int port;
    private long elapsedTime;

    private String importcert = "false";
    private boolean impStatus = false;

    // Constructors

    /**
     * Constructor . Takes the parameter for Properties file name
     * <p>
     * @param propfilename  name of the parameter file
     */

    public DirEnroll(String pfile) {
        propfileName = pfile;
    }

    /**
     * Constructor. Takes hostname , EESSLportnumber as parameter
     * <p>
     * @param hostname
     * @param portnumber
     */

    public DirEnroll(String h, String p) {
        host = h;
        ports = p;
    }

    /**
     * Constructor. Takes hostname,EESSLportnumber,uid,password,certdbdirectorypath,certdbpassword,certificatenickname,keysize,teytype 
     * <p>
     * @param hostname
     * @param portnumber
     * @param subjectdn
     * @param admuserid
     * @param adminpassword
     */


    public DirEnroll(String hs, String p, String uid, String pw, String certdir, String certtokenpwd, String nickname, String ksz, String kt) {

        host = hs;
        ports = p;
        UID = uid;
        PWD = pw;
        cdir = certdir;
        tokenpwd = certtokenpwd;
        certnickname = nickname;
        keysize = "1024";
        keytype = "RSA";
    }

    // Set and Get functions 

    /**
     * Use this method to set User Info 
     */ 
    public void setUIDInfo(String uid, String pw) {
        UID = uid;
        PWD = pw;
    }

    /**
     *  Returns a string "UserDir" / "Portal"
     */

    public String getAuthenticator() {
        return Authenticator;
    }

    /**
     *  Valid values for  s - UserDir for Directory based Authntication
     *                        Portal  for Portal based Authentication
     */
    public void  setAuthenticator(String s) {
        Authenticator = s;
    }

    public boolean enroll_load() {
        buildquery();
        return(Send());
    }

    private boolean pkcs10() {
        System.out.println(" In pkcs10 Keysize ,  key type " + keysize + keytype);
        cCrypt.setCertDir(cdir);
        cCrypt.setCertnickname("cn=test");
        cCrypt.setKeySize(keysize);
        cCrypt.setKeyType(keytype);
        cCrypt.setTokenPWD(tokenpwd);
	
        cCrypt.setDebug(debug);
        cCrypt.setGenerateRequest(true);
        if (!cCrypt.generateRequest()) {
            System.out.println("Request could not be generated ");
            return false;
        }
        pkcs10request = cCrypt.getPkcs10Request();

        try {
            buildquery();
            System.out.println(query);
            setStatusString("Congratulations, your certificate has been issued.");
            return(Send());		
        } catch (Exception e) {
            System.err.println("some exception:" + e);
        }

        return false;

    }

    /**
     * Enroll for certificate . Before calling this mentod SetAuthenticator and setUIDInfo 
     */
    public boolean enroll() {
        return(pkcs10());
    }

    private boolean readProperties() {

        // Read the properties file and assign values to variables .
        try {
            getProperties(propfileName);
        } catch (Exception e) {
            System.out.println(
                    "exception reading Properties File " + e.getMessage());
            return false;
        }

        System.out.println("Reading");
        host = props.getProperty("enroll.host");
        ports = props.getProperty("enroll.port");
        UID = props.getProperty("enroll.UID");
        PWD = props.getProperty("enroll.pwd");
        cdir = props.getProperty("enroll.certdir");
        tokenpwd = props.getProperty("enroll.certtokenpwd");
        certnickname = props.getProperty("enroll.nickname");
        keysize = props.getProperty("enroll.keysize");
        keytype = props.getProperty("enroll.keytype");
        Authenticator = props.getProperty("enroll.authenticator");
        GN = props.getProperty("enroll.GN");
        SN = props.getProperty("enroll.SN");
        CN = props.getProperty("enroll.CN");
        OU = props.getProperty("enroll.OU");
        O = props.getProperty("enroll.O");
        MAIL = props.getProperty("enroll.mail");
        L = props.getProperty("enroll.l");

        importcert = props.getProperty("enroll.importCert");
        if (importcert == null) {
            importcert = "false";
        }
        String de = props.getProperty("enroll.debug");

        if (de == null) {
            debug = false;
        } else if (de.equals("true")) {
            debug = true;
        } else {
            debug = false;
        }

        System.out.println("Reading done");
        // Enroll using a pkscks10 request
        return true;
    }

    // Private functions 

    private boolean importCert(String certpack) {

        if (importcert.equals("false")) {
            return true;
        }

        try {
            if (certpack == null) {
                return false;
            }

            if (debug) {
                System.out.println(
                        "importing cert" + certpack + "certnick" + certnickname);
            }

            cCrypt.importCert(certpack, certnickname);

            return true;

        } catch (Exception e) {
            System.out.println("exception importing cert " + e.getMessage());
            return false;
        }

    }

    private void setElapsedTime(long dif) {
        elapsedTime = dif;
    }

    private long calculateElapsedTime(GregorianCalendar b, GregorianCalendar e) {

        Date d1 = b.getTime();
        Date d2 = e.getTime();
        long l1 = d1.getTime();
        long l2 = d2.getTime();
        long difference = l2 - l1;

        return difference;

    }

    private boolean Send() {
        boolean st = false;

        try {
            if (debug) {
                System.out.println("Step 3 : Socket initialize");
            }

            Integer x = new Integer(ports);

            port = x.intValue();
            ErrorDetail = null;
            GregorianCalendar begin = new GregorianCalendar();

            // SSLSocket socket = new SSLSocket(host,port);
            SSLSocket socket = new SSLSocket(host, port, null, 0, this, null);

            socket.setUseClientMode(true);

            OutputStream rawos = socket.getOutputStream();
            BufferedOutputStream os = new BufferedOutputStream(rawos);
            PrintStream ps = new PrintStream(os);

            ps.println("POST /enrollment HTTP/1.0");
            ps.println("Connection: Keep-Alive");
            ps.println("Content-type: application/x-www-form-urlencoded");
            ps.println("Content-length: " + query.length());
            ps.println("");
            ps.println(query);
            ps.println("\r");
            ps.flush();
            os.flush();
            BufferedReader stdin = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));

            if (debug) {
                System.out.println("Step 4: Received the page");
            }
            st = false;
            String line;

            while ((line = stdin.readLine()) != null) {
                if (debug) {
                    System.out.println(line);
                }
                if (line.indexOf(STATUS) != -1) {
                    st = true;
                }
                if (getError(line)) {
                    st = true;
                }

                if (line.indexOf("record.base64Cert=") > -1) {
                    String  baseCert = line;

                    System.out.println("BaseCert : " + baseCert);
                    if (importcert.equals("true")) {
                        String strbase = "record.base64Cert=";

                        int n = strbase.length() + 1;

                        baseCert = baseCert.substring(n);
                        String tmp = baseCert.substring(0, baseCert.length() - 2);

                        if (importCert(tmp)) {
                            impStatus = true;
                        }
                    } else {
                        impStatus = true;
                    }
                }

            }
            stdin.close();
            socket.close();
            os.close();
            rawos.close();
            ps.close();
            os = null;
            rawos = null;
            stdin = null;
            ps = null;
            line = null;

            GregorianCalendar end = new GregorianCalendar();
            long diff = calculateElapsedTime(begin, end);

            setElapsedTime(diff);

        } catch (Exception e) {
            System.err.println("some exception: in Send routine" + e);
            return false;
        }

        return st;
 
    }

    private void buildquery() {

        StringBuffer queryStrBuf = new StringBuffer();
	
        queryStrBuf.append("certType=client");
        queryStrBuf.append("&importCert=off");
        queryStrBuf.append("&non_repudiation=true");
        queryStrBuf.append("&submit=Submit");
        queryStrBuf.append("&key_encipherment=true");
        queryStrBuf.append("&digital_signature=true");
        queryStrBuf.append("&ssl_client=true");

        System.out.println("Authenticator : " + Authenticator);

        if (Authenticator.equals("UserDir")) {
            queryStrBuf.append("&authenticator=UserDirEnrollment");
            queryStrBuf.append("&requestFormat=keygen");
            queryStrBuf.append("&uid=");
            queryStrBuf.append(URLEncoder.encode(UID));
            queryStrBuf.append("&pwd=");
            queryStrBuf.append(URLEncoder.encode(PWD));
            queryStrBuf.append("&email=true");	
            queryStrBuf.append("&cryptprovider=1");

        }

        if (Authenticator.equals("Portal")) {
            queryStrBuf.append("&authenticator=PortalEnrollment");
            queryStrBuf.append("&requestFormat=keygen");
            queryStrBuf.append("&uid=");
            queryStrBuf.append(URLEncoder.encode(UID));
            queryStrBuf.append("&userPassword=");
            queryStrBuf.append(URLEncoder.encode(PWD));
            GN = "test";
            SN = "test";
            CN = "test";
            MAIL = "test@netscape.com";
            OU = "aol";
            O = "aol";
            L = "MV";
            queryStrBuf.append("&givenname=");
            queryStrBuf.append(URLEncoder.encode(GN));

            queryStrBuf.append("&sn=");
            queryStrBuf.append(URLEncoder.encode(SN));
            queryStrBuf.append("&cn=");
            queryStrBuf.append(URLEncoder.encode(CN));

            queryStrBuf.append("&mail=");
            queryStrBuf.append(URLEncoder.encode(MAIL));
            queryStrBuf.append("&ou=");
            queryStrBuf.append(URLEncoder.encode(OU));
            queryStrBuf.append("&o=");
            queryStrBuf.append(URLEncoder.encode(O));
            queryStrBuf.append("&l=");
            queryStrBuf.append(URLEncoder.encode(L));

            queryStrBuf.append("&email=true");	

        }

        if (Authenticator.equals("NIS")) {
            queryStrBuf.append("&authenticator=NISAuth");
            queryStrBuf.append("&requestFormat=keygen");
            queryStrBuf.append("&uid=");
            queryStrBuf.append(URLEncoder.encode(UID));
            queryStrBuf.append("&pwd=");
            queryStrBuf.append(URLEncoder.encode(PWD));
            queryStrBuf.append("&email=true");	

        }

        queryStrBuf.append("&pkcs10Request=");
        queryStrBuf.append(URLEncoder.encode(pkcs10request));
        query = queryStrBuf.toString();

        System.out.println(query);
   
    }

    public static void main(String args[]) {
        // Exit Status - (0) for error/Fail
        // - requestId Pass
        boolean st;
  
        System.out.println(args.length);
        if (args.length < 1) {
            System.out.println("Usage : propertiesfile");
            System.exit(0);
        }   

        DirEnroll t = new DirEnroll(args[0]);

        t.readProperties();
        st = t.enroll();
        if (st) { 
            System.out.println(
                    t.getAuthenticator() + " based enrollment successfull. ");
            System.exit(1);
        } else {

            System.out.println(
                    t.getAuthenticator()
                            + " based enrollment was not successful."
                            + "Error: " + t.getErrorDetail());
            System.exit(0);
        }
    }// end of function main

} // end of class 

