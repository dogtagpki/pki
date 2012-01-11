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
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintStream;
import java.util.Date;
import java.util.GregorianCalendar;

import org.mozilla.jss.ssl.SSLSocket;

/**
 * CMS Test framework .
 * Submits a checkRequestStatus request to the server. parses the response from server and can import cert to the specified client database.
 * <P>
 */

public class checkRequest extends TestClient {

    private int i;
    private String certfile, importcert = "false", certnickname, serialNumber, ldapformat;

    private String requestId;
    private String reqStatus = "false";
    private String pkcsCert, baseCert, ACTION_STRING, issuer, subject, AUTH = "ca";
    private int port;
    private boolean impStatus = false;
    private int type = 1;

    private long elapsedTime;

    private String host;
    private String ports;
    private String tokenpwd;
    private String cdir;

    // public methods 

    /**
     * Constructor . Takes the parameter for Properties file name
     * <p>
     * 
     * @param propfilename name of the parameter file
     */

    public checkRequest(String pfile) {
        propfileName = pfile;
    }

    /**
     * Constructor . Takes the parameter for hostname and EESSLportnumber
     * <p>
     */

    public checkRequest(String h, String p) {
        host = h;
        ports = p;
    };

    /**
     * Constructor . Takes the parameter for hostname , EESSLportnumber , Requestnumber and ImportCert ( true/false)
     * <p>
     */

    public checkRequest(String h, String p, String snum, String impc) {
        host = h;
        ports = p;
        requestId = snum;
        importcert = impc;
    }

    /**
     * Constructor . Takes the parameter for hostname , EESSLportnumber , certdbdir, certdbpassword, Requestnumber ,certnickname and ImportCert ( true/false)
     * <p>
     */

    public checkRequest(String hs, String pt, String certdir, String certtokenpwd, String seqnum, String nickname, String impc) {
        host = hs;
        ports = pt;
        cdir = certdir;
        tokenpwd = certtokenpwd;
        requestId = seqnum;
        if (impc == null) {
            importcert = "false";
        } else {
            importcert = impc;
        }
        certnickname = nickname;

    }

    public void setDebug(boolean t) {
        debug = t;
    }

    public void setreqId(String seqnum) {
        requestId = seqnum;
    }

    public void setCertNickname(String cname) {
        certnickname = cname;
    }

    /**
     * takes values - true/false
     **/
    public void setImportCert(String impc) {
        importcert = impc;
    }

    public String getpkcs7ChainCert() {
        return pkcsCert;
    }

    /**
     * returns Certificate
     **/

    public String getCert() {
        return cCrypt.normalize(baseCert);
    }

    /**
     * returns Request status - "complete","pending"
     **/

    public String getRequestStatus() {
        return reqStatus;
    }

    /**
     * returns the hex serial number of the certificate
     **/

    public String getSerialNumberHex() {
        return serialNumber;
    }

    /**
     * returns the serial number as interger
     **/

    public int getSerialNumber() {
        if (serialNumber != null) {
            Integer y = new Integer(Integer.parseInt(serialNumber, 16));

            return y.intValue();
        }
        return 0;
    }

    /**
     * Submits a checkRequestStatus request to the server
     **/

    public boolean checkRequestStatus() {

        // Login to dB and genertae request
        cCrypt.setCertDir(cdir);
        cCrypt.setCertnickname(certnickname);
        cCrypt.setKeySize(keysize);
        cCrypt.setKeyType(keytype);
        cCrypt.setTokenPWD(tokenpwd);
        cCrypt.setDebug(debug);

        if (!cCrypt.loginDB()) {
            System.out.println("Error : Login certdb failed ");
            System.err.println("FAIL : Login certdb failed ");
            return false;
        }

        try {

            type = 1;
            buildquery();
            if (debug) {
                System.out.println(query);
            }
            setStatusString("Congratulations, your certificate has been issued.");
            if (Send()) {
                if (debug) {
                    System.out.println("Request Status :" + reqStatus);
                }
                if (reqStatus.equals("complete")) {
                    type = 2;
                    buildquery();
                    if (debug) {
                        System.out.println(query);
                    }
                    if (Send()) {
                        return true;
                    }
                } else {
                    return true;
                }

            }
            if (debug) {
                System.out.println("Request Status :" + reqStatus);
            }

            System.err.println("FAIL: reached end of checkRequestStatus()");

            return false;
        } catch (Exception e) {
            System.err.println("some exception:" + e);
        }

        return false;
    }

    // Private functions 

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

    private boolean writeCert2File() {
        if (serialNumber != null) {

            try {
                FileOutputStream fos = new FileOutputStream(certfile);

                if (ldapformat.equals("true")) {
                    Integer m = new Integer("1");
                    String tmp = "description: 2;"
                            + Integer.parseInt(serialNumber, 16) + ";" + issuer
                            + ";" + subject + "\n";

                    fos.write(tmp.getBytes());
                    tmp = cCrypt.normalizeForLDAP(getCert());
                    if (debug) {
                        System.out.println(tmp);
                    }
                    fos.write(("usercertificate:: ").getBytes());
                    fos.write(tmp.getBytes());
                    fos.close();
                } else {
                    String tmp = cCrypt.normalize(getCert());

                    if (debug) {
                        System.out.println(tmp);
                    }
                    fos.write(tmp.getBytes());
                    fos.close();

                }

            } catch (Exception e) {
                System.out.println(
                        "exception in writeCert2File: " + e.getMessage());
                return false;
            }

        }

        return true;
    }

    private boolean importCert(String certpack) {

        if (importcert.equals("false")) {
            return true;
        }

        try {
            if (certpack == null) {
                return false;
            }

            String s = cCrypt.normalize(certpack);

            if (AUTH.equals("ca")) {
                String tmp = "-----BEGIN CERTIFICATE-----\n" + s + "\n"
                        + "-----END CERTIFICATE-----";

                if (debug) {
                    System.out.println(
                            "importing cert" + tmp + "certnick" + certnickname);
                }
                s = tmp;
            }

            if (cCrypt.importCert(s, certnickname)) {
                System.out.println("successfully imported cert");
                return true;
            }

            return false;

        } catch (Exception e) {
            System.out.println(
                    "exception importing cert  crequest" + e.getMessage());
            return false;
        }

    }

    private boolean RetrieveRequestDetail(String line) {
        String stat = "header.status = ";
        boolean st = true;

        if (debug) {
            System.out.println(line);
        }

        if (line.indexOf(stat) != -1) {
            String tm = line.substring(stat.length() + 1,
                    line.indexOf(";", 10) - 1);

            reqStatus = tm;
        }
        if (line.indexOf("header.pkcs7ChainBase64 = ") != -1) {
            // if status is complete retrieve cert
            pkcsCert = line.substring("header.pkcs7ChainBase64 = ".length() + 1,
                    line.indexOf(";", 10) - 1);
        }
        if (line.indexOf("record.serialNumber=") != -1) {
            serialNumber = line.substring("record.serialNumber=".length() + 1,
                    line.indexOf(";", 1) - 1);
        }
        if (line.indexOf("header.authority =") == 0) {
            AUTH = line.substring("header.authority =".length() + 2,
                    line.indexOf(";", 1) - 1);
        }

        if (getError(line)) {
            st = false;
        }

        return st;

    }

    private boolean RetrieveCertDetails(String line) {
        if (debug) {
            System.out.println(line);
        }

        boolean st = true;

        String retriveStr[] = {
                "record.base64Cert=", "record.certPrettyPrint=",
                "header.certChainBase64 = ", "header.certPrettyPrint = " };
        String baseCertStr, certPrettyprintStr;

        if (AUTH.equals("ra")) {
            baseCertStr = retriveStr[0];
            certPrettyprintStr = retriveStr[1];
        } else {
            baseCertStr = retriveStr[2];
            certPrettyprintStr = retriveStr[3];
        }

        if (line.indexOf(baseCertStr) != -1) {

            // if status is complete retrieve cert
            baseCert = line.substring(baseCertStr.length() + 1,
                    line.indexOf(";", 10) - 1);
            if (importcert.equals("true")) {
                if (importCert(baseCert)) {
                    st = true;
                }
            } else {
                st = true;
            }
        }

        if (line.indexOf(certPrettyprintStr) != -1) {

            System.out.println("Found certPrettyPrint");
            int ret = line.indexOf("Issuer: ");

            issuer = line.substring(("Issuer: ").length() + ret,
                    line.indexOf("Validi", ret) - 14);
            ret = line.indexOf("Subject:");
            subject = line.substring(("Subject: ").length() + ret,
                    line.indexOf("Subject Public", ret) - 14);

            System.out.println(" HEADER : " + issuer);

        }

        // System.out.println("Debug :get Error detail " + line);
        if (getError(line)) {
            st = false;
        }

        return st;

    }

    private synchronized boolean Send() {
        boolean st = false;

        try {
            if (debug) {
                System.out.println("Step 3 : Socket initialize");
            }

            Integer x = new Integer(ports);

            port = x.intValue();

            GregorianCalendar begin = new GregorianCalendar();

            impStatus = false;

            // SSLSocket socket = new SSLSocket(host,port);
            SSLSocket socket = new SSLSocket(host, port, null, 0, this, null);

            socket.setUseClientMode(true);

            OutputStream rawos = socket.getOutputStream();
            BufferedOutputStream os = new BufferedOutputStream(rawos);
            PrintStream ps = new PrintStream(os);

            ps.println("POST " + ACTION_STRING + " HTTP/1.0");
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
                switch (type) {
                case 1:
                    RetrieveRequestDetail(line);
                    st = true;
                    break;

                case 2:
                    st = RetrieveCertDetails(line);
                    break;

                default:
                    System.out.println("invalid format");

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
        if ((certfile != null) && (type == 2)) {
            st = writeCert2File();
        }

        if (debug) {
            System.out.println(serialNumber);
        }

        return st;

    }

    private void buildquery() {

        StringBuffer queryStrBuf = new StringBuffer();

        if (type == 1) {
            ACTION_STRING = "/checkRequest";
            queryStrBuf.append("requestId=");
            queryStrBuf.append(requestId);
            queryStrBuf.append("&importCert=true");
        }

        if (type == 2) {
            ACTION_STRING = "/" + AUTH + "/displayBySerial";
            if (AUTH.equals("ra")) {
                ACTION_STRING = "/displayCertFromRequest";
                queryStrBuf.append("requestId=");
                queryStrBuf.append(requestId);

            } else {
                ACTION_STRING = "/displayBySerial";
                queryStrBuf.append("op=displayBySerial");
                queryStrBuf.append("&serialNumber=0x");
                queryStrBuf.append(serialNumber);
            }
        }

        query = queryStrBuf.toString();

        queryStrBuf = null;

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

        host = props.getProperty("enroll.host");
        ports = props.getProperty("enroll.port");
        cdir = props.getProperty("enroll.certdir");
        tokenpwd = props.getProperty("enroll.certtokenpwd");
        requestId = props.getProperty("enroll.seqnum");
        certfile = props.getProperty("enroll.certfile");
        importcert = props.getProperty("enroll.importCert");
        if (importcert == null) {
            importcert = "false";
        }
        ldapformat = props.getProperty("enroll.ldapformat");
        if (ldapformat == null) {
            ldapformat = "true";
        }
        System.out.println(ldapformat);
        certnickname = props.getProperty("enroll.nickname");
        String de = props.getProperty("enroll.debug");

        if (de == null) {
            debug = false;
        } else if (de.equals("true")) {
            debug = true;
        } else {
            debug = false;
        }

        // Enroll using a pkscks10 request
        return (checkRequestStatus());
    }

    public static void main(String args[]) {
        // Exit Status - (0) for error/Fail
        // - requestId Pass
        boolean st;

        if (args.length < 1) {
            System.out.println("Usage : propertiesfile");
            System.exit(0);
        }

        checkRequest t = new checkRequest(args[0]);

        st = t.readProperties();
        if (st) {
            System.exit(t.getSerialNumber());
        } else {

            System.out.println("Request Status :" + t.getRequestStatus());
            System.out.println("Error: " + t.getErrorDetail());

            System.exit(0);
        }
    }// end of function main

} // end of class 

