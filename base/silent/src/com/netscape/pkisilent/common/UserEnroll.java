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
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Date;
import java.util.GregorianCalendar;

import org.mozilla.jss.ssl.SSLSocket;

/**
 * CMS Test framework .
 * Submits Legacy Manual User Enrollment request from EESSL port. Parses the response from server and return RequestID.
 * <P>
 */

public class UserEnroll extends TestClient {

    private String requestorName, requestorEmail, requestorPhone, requestorComments, requestId, certType, ssl_client;
    private int port;
    @SuppressWarnings("unused")
    private long elapsedTime;

    // Constructor
    public UserEnroll() {
    }

    /**
     * Constructor . Takes the parameter hostname and EESSLport
     * <p>
     */

    public UserEnroll(String h, String p) {
        host = h;
        ports = p;
    }

    /**
     * Constructor . Takes the parameter for Properties file name
     * <p>
     *
     * @param propfilename name of the parameter file
     */

    public UserEnroll(String pfile) {
        propfileName = pfile;
    }

    /**
     * Constructor . Takes the parameter for hostname, EESSLportnumber, subjectdn, E, CN,UID,OU,O,
     * CertdbDirecrory(fullpath) , certdbPassword, keysize, keytype, requestorName,requestorEmail and Certtype.
     * valid values for Certtype - "ca","ra","ocsp"
     * <p>
     *
     * @param propfilename name of the parameter file
     */

    public UserEnroll(String h, String p, String dn, String e, String cn, String uid, String ou, String o, String cd,
            String tpwd, String sslcl, String ksize, String keyty, String reqname, String reqemail, String ctype) {

        host = h;
        ports = p;
        DN = dn;
        E = e;
        CN = cn;
        UID = uid;
        OU = ou;
        O = o;
        C = "US";
        cdir = cd;
        tokenpwd = tpwd;
        ssl_client = sslcl;
        keysize = ksize;
        keytype = keyty;
        requestorName = reqname;
        requestorPhone = "650";
        requestorEmail = "lg";
        requestorComments = "load Test";
        certnickname = "cn=test";
        keytype = "RSA";
        keysize = "1024";
        certType = ctype;
        if (certType.equals("caSigningCert")) {
            certType = "ca";
        }
        if (certType.equals("raSigningCert")) {
            certType = "ra";
        }
        if (certType.equals("ocspSigningCert")) {
            certType = "ocsp";
        }
    }

    /**
     * Set Certificate Request information. Takes parameters - subjectdn,E,CN,UID,OU,O
     */

    public void setUserInfo(String dn, String e, String cn, String uid, String ou, String o) {
        DN = dn;
        E = e;
        CN = cn;
        UID = uid;
        OU = ou;
        O = o;
        requestorName = "test";
        requestorPhone = "650";
        requestorEmail = "lg";
        requestorComments = "Test";
        certnickname = "cn=test";

    }

    public void setUserInfo(String dn, String e, String cn, String uid, String ou, String o, String nickname) {
        DN = dn;
        E = e;
        CN = cn;
        UID = uid;
        OU = ou;
        O = o;
        requestorName = "test";
        requestorPhone = "650";
        requestorEmail = "lg";
        requestorComments = "Test";
        certnickname = nickname;

    }

    /**
     * Set Certificat Type for which you want to submit a request . Valid values - "ca"/"ra"/"ocsp"
     */
    public void setCertType(String ct) {
        certType = ct;
    }

    public boolean enroll_load() throws UnsupportedEncodingException {
        buildquery();
        setStatusString("");
        return (Send());
    }

    private boolean pkcs10() {

        System.out.println(" In pkcs10 Keysize ,  key type " + keysize + keytype);
        // ComCrypto cCrypt = new ComCrypto(cdir,tokenpwd,certnickname,keysize,keytype);
        cCrypt.setCertDir(cdir);
        cCrypt.setCertnickname(adminCertName);
        cCrypt.setKeySize(keysize);
        cCrypt.setKeyType(keytype);
        cCrypt.setTokenPWD(tokenpwd);
        cCrypt.setDebug(true);
        if (pkcs10request != null) {
            cCrypt.setGenerateRequest(false);
            cCrypt.loginDB();
        } else {
            cCrypt.setGenerateRequest(true);
            if (!cCrypt.generateRequest()) {
                System.out.println("Request could not be generated ");
                return false;
            }
            pkcs10request = cCrypt.getPkcs10Request();
        }

        try {
            System.out.println("Debug: building query ");
            buildquery();
            if (debug) {
                System.out.println(query);
            }
            setStatusString("");
            return (Send());
        } catch (Exception e) {
            System.err.println("some exception:" + e);
        }

        return (false);

    }

    // Private methods

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
                if (line.indexOf("fixed.requestId = ") != -1) {
                    requestId = line.substring("fixed.requestId = ".length() + 1,
                            line.indexOf(";") - 1);
                }

                if (getError(line)) {
                    st = false;
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

    private void buildquery() throws UnsupportedEncodingException {

        StringBuffer queryStrBuf = new StringBuffer();

        if (certType.equals("client")) {
            queryStrBuf.append("certType=");
            queryStrBuf.append(certType);
            queryStrBuf.append("&Send=submit");

            queryStrBuf.append("&key_encipherment=true");

            queryStrBuf.append("&digital_signature=true");

            queryStrBuf.append("&requestFormat=keygen");

            queryStrBuf.append("&cryptprovider=1");
            if (ssl_client.equals("true")) {
                queryStrBuf.append("&ssl_client=true");
            } else {
                queryStrBuf.append("&ssl_server=true");
            }

            queryStrBuf.append("&non_repudiation=true");

            if (requestorName.length() > 0) {
                queryStrBuf.append("&csrRequestorName=");
            }
            queryStrBuf.append(URLEncoder.encode(requestorName, "UTF-8"));
            if (requestorEmail.length() > 0) {
                queryStrBuf.append("&csrRequestorEmail=");
                queryStrBuf.append(URLEncoder.encode(requestorEmail, "UTF-8"));
                queryStrBuf.append("&email=true");

            } else {
                queryStrBuf.append("&email=false");
            }

            if (requestorPhone.length() > 0) {
                queryStrBuf.append("&csrRequestorPhone=");
                queryStrBuf.append(URLEncoder.encode(requestorPhone, "UTF-8"));
            }
            if (requestorComments.length() > 0) {
                queryStrBuf.append("&csrRequestorComments=");
                queryStrBuf.append(URLEncoder.encode(requestorComments, "UTF-8"));
            }
            System.out.println("buidlquery client E ");
            if (E.length() > 0) {
                queryStrBuf.append("&E=");
                queryStrBuf.append(E);
            }
            if (CN.length() > 0) {
                queryStrBuf.append("&CN=");
                queryStrBuf.append(CN);
            }

            if (UID.length() > 0) {
                queryStrBuf.append("&UID=");
                queryStrBuf.append(UID);
            }
            if (OU.length() > 0) {
                queryStrBuf.append("&OU=");
                queryStrBuf.append(OU);
            }
            // if(O.length() > 0) {	queryStrBuf.append("&O=");queryStrBuf.append(O);}
            // if(C.length() >0) {	queryStrBuf.append("&C=");queryStrBuf.append(C);}
            System.out.println("buidlquery client dn ");
            queryStrBuf.append("&subject=");
            queryStrBuf.append(URLEncoder.encode(DN, "UTF-8"));
        }

        if (certType.equals("ra")) {
            queryStrBuf.append("certType=" + certType);
            queryStrBuf.append("&digital_signature=true");
            queryStrBuf.append("&non_repudiation=true");
            queryStrBuf.append("&ssl_client=true");
        }

        if (certType.equals("server")) {
            queryStrBuf.append("certType=" + certType);
            queryStrBuf.append("&digital_signature=true");
            queryStrBuf.append("&non_repudiation=true");
            queryStrBuf.append("&ssl_server=true");
            queryStrBuf.append("&key_encipherment=true");
            queryStrBuf.append("&data_encipherment=true");

        }

        if (certType.equals("ocsp")) {
            queryStrBuf.append("certType=ocspResponder");
            queryStrBuf.append("&digital_signature=true");
            queryStrBuf.append("&non_repudiation=true");
            queryStrBuf.append("&ssl_client=true");
        }

        if (certType.equals("ca")) {
            queryStrBuf.append("certType=" + certType);
            queryStrBuf.append("&digital_signature=true");
            queryStrBuf.append("&non_repudiation=true");
            queryStrBuf.append("&ssl_client=true");
            queryStrBuf.append("&object_signing_ca=true");
            queryStrBuf.append("&crl_sign=true");
            queryStrBuf.append("&ssl_ca=true");
            queryStrBuf.append("&key_certsign=true");
            queryStrBuf.append("&email_ca=true");

        }

        queryStrBuf.append("&pkcs10Request=");
        queryStrBuf.append(URLEncoder.encode(pkcs10request, "UTF-8"));
        System.out.println("before converting bug to string ");
        query = queryStrBuf.toString();

        System.out.println(query);
        queryStrBuf = null;
    }

    public int getRequestId() {
        Integer m = new Integer(requestId);

        return m.intValue();

    }

    /**
     * Submit enrollment request
     */

    public boolean clientCertEnroll() {
        certType = "client";
        ssl_client = "true";
        debug = true;
        return (pkcs10());
    }

    public boolean Enroll() {
        debug = true;
        return (pkcs10());
    }

    /**
     * Read the properties file
     **/

    public boolean readProperties() {

        // Read the properties file and assign values to variables .
        try {
            getProperties(propfileName);
        } catch (Exception e) {
            System.out.println(
                    "exception reading Properties File " + e.getMessage());
            return false;
        }

        host = props.getProperty("enroll.host");
        ports = props.getProperty("enroll.port");
        DN = props.getProperty("enroll.DN");
        requestorName = props.getProperty("enroll.name");
        requestorEmail = props.getProperty("enroll.email");
        requestorPhone = props.getProperty("enroll.phone");
        requestorComments = props.getProperty("enroll.comments");
        E = props.getProperty("enroll.E");
        CN = props.getProperty("enroll.CN");
        UID = props.getProperty("enroll.UID");
        OU = props.getProperty("enroll.OU");
        O = props.getProperty("enroll.O");
        C = props.getProperty("enroll.C");
        cdir = props.getProperty("enroll.certdir");
        tokenpwd = props.getProperty("enroll.certtokenpwd");
        certnickname = props.getProperty("enroll.nickname");
        keysize = props.getProperty("enroll.keysize");
        keytype = props.getProperty("enroll.keytype");
        certType = props.getProperty("enroll.certtype");
        if (certType == null) {
            certType = "client";
        }
        if (certType.equals("raSigningCert")) {
            certType = "ra";
        }
        if (certType.equals("ocspSigningCert")) {
            certType = "ocsp";
        }
        pkcs10request = props.getProperty("enroll.pkcs10");
        ssl_client = props.getProperty("enroll.sslclient");
        if (ssl_client == null) {
            ssl_client = "true";
        }

        String de = props.getProperty("enroll.debug");

        if (de == null) {
            debug = false;
        } else if (de.equals("true")) {
            debug = true;
        } else {
            debug = false;
        }

        // Enroll using a pkscks10 request
        return (pkcs10());
    }

    public static void main(String args[]) {
        // Exit Status - (0) for error/Fail
        // - requestId Pass

        UserEnroll e = new UserEnroll("jupiter2", "1027",
                "E=test,cn=test,uid=test", "test", "test", "test", "t1", "t",
                "/u/lgopal/work/tetCMS/ns/tetframework/testcases/CMS/6.0/acceptanceJava/data/certdb",
                "secret12", "true", "1024", "RSA", "rn", "re", "client");

        e.clientCertEnroll();

        /* if ( args.length < 1)
         {
         System.out.println("Usage : propertiesfile");
         System.exit(0);
         }


         UserEnroll t = new UserEnroll(args[0]);
         st=t.enroll();
         if (st){
         System.out.println("User Enrolled successfully . RequestId is "+t.getrequestId());
         System.exit(t.getRequestId());
         }
         else{

         System.out.println("Error: " + t.getErrorDetail());
         System.exit(0);
         }
         */
    }// end of function main

} // end of class

