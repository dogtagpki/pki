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
package com.netscape.admin.certsrv.security;

/**
 *
 *  Parse the response that was sent back by the cgi
 *
 */

import java.util.*;
import java.io.*;
import com.netscape.management.client.util.Debug;

//this class need some optimization....

class Response {

    String _response;
    String _cert = "";
    Vector _messages = new Vector();
    Vector _certList = null;
    CertInfo _certInfo = null;
    Hashtable _certInstInfo = null;

    Hashtable _ssl2Preference = null;
    Hashtable _ssl3Preference = null;

    String startCert = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    String endCert = "-----END NEW CERTIFICATE REQUEST-----";
    String startCertList = "-----BEGIN CERT LIST-----";
    String endCertList = "-----END CERT LIST-----";
    String startCertInfo = "-----BEGIN CERTIFICATE INFO-----";
    String endCertInfo = "-----END CERTIFICATE INFO-----";
    String startCRLCertInfo = "-----BEGIN CRL INFO-----";
    String endCRLCertInfo = "-----END CRL INFO-----";

    String startCertInstInfo = "-----BEGIN CERTIFICATE INSTALL INFO-----";
    String endCertInstInfo = "-----END CERTIFICATE INSTALL INFO-----";
    String startCRLCertInstInfo = "-----BEGIN CRL INSTALL INFO-----";
    String endCRLCertInstInfo = "-----END CRL INSTALL INFO-----";

    boolean _fCert = false, _fCertList = false, _fCertInfo = false,
    _fCertInstInfo = false;
    boolean _fsecurityDomestic = false, _fsecurityFortezza = false;

    void parseCertificate(String response) {
        if (response.indexOf(startCert) != -1) {
            _cert = response.substring(response.indexOf(startCert),
                    response.indexOf(endCert) + endCert.length());
            _fCert = true;
        }
    }

    void parseCertificateList(String response) {
        if (response.indexOf(startCertList) != -1) {
            _certList = new Vector();

            try {
                BufferedReader stream =
                        new BufferedReader(new StringReader(response));
                while (!(stream.readLine().equals(startCertList))) {
                }

                String line;
                while (!((line = stream.readLine()).equals(endCertList))) {
                    //need to hack the string that return by the NS secutiry code.
                    //it assumes we are working with html
                    line = urlDecode(line);
                    StringTokenizer token =
                            new StringTokenizer(line, "=;\n", false);
                    Debug.print(line);

                    String certName = "", certType = "", certExpire = "";
                    try {
                        certName = token.nextToken();
                        certType = token.nextToken();
                        certExpire = token.nextToken();
                    } catch (NoSuchElementException noToken) { }

                    _certList.addElement(
                            new CertBasicInfo(certName, certType,
                            certExpire));
                }
            } catch (IOException e) {
                Debug.println(e.getMessage());
            }

            _fCertList = true;
        }

    }

    void parseCertificateInfo(String response) {
        if ((response.indexOf(startCertInfo) != -1) ||
                (response.indexOf(startCRLCertInfo) != -1)) {

            try {
                BufferedReader stream =
                        new BufferedReader(new StringReader(response));
                String line;
                while (! (((line =
                        stream.readLine()).equals(startCertInfo)) ||
                        (line.equals(startCRLCertInfo)))) {
                }

                String issuer = "", subject = "", serialNumber = "",
                version = "", validFrom = "", validTo = "";
                String fingerPrint = "", trustCert = "", certName = "",
                certDeleted = "0", certTitle = "";

                while (!((line = stream.readLine()).equals(endCertInfo))
                        && !(line.equals(endCRLCertInfo))) {

                    //need to hack the string that was returned by the NS secutiry code.
                    //it assumes we are working with html
                    line = urlDecode(line);
                    StringTokenizer token =
                            new StringTokenizer(line, "=\n", false);
                    Debug.print(line);


                    try {
                        String keyWord = token.nextToken();
                        if (keyWord.equals("ISSUER")) {
                            //have to hack again because of the stupid html in the data
                            issuer = KeyCertUtility.replace(
                                    token.nextToken(), "<br>", "\n");
                            ;
                        } else if (keyWord.equals("SUBJECT")) {
                            subject = KeyCertUtility.replace(
                                    token.nextToken(), "<br>", "\n");
                            ;
                        } else if (keyWord.equals("SERIALNUMBER")) {
                            serialNumber = token.nextToken();
                        } else if (keyWord.equals("VERSION")) {
                            version = token.nextToken();
                        } else if (keyWord.equals("NOTBEFORE")) {
                            validFrom = token.nextToken();
                        } else if (keyWord.equals("NOTAFTER")) {
                            validTo = token.nextToken();
                        } else if (keyWord.equals("FINGERPRINT")) {
                            fingerPrint = token.nextToken();
                        } else if (keyWord.equals("TRUSTED")) {
                            trustCert = token.nextToken();
                        } else if (keyWord.equals("CERTNAME")) {
                            certName = token.nextToken();
                        } else if (keyWord.equals("CERTDELETED")) {
                            certDeleted = token.nextToken();
                        } else if (keyWord.equals("CERTTITLE")) {
                            certTitle = token.nextToken();
                        }
                    } catch (NoSuchElementException noToken) {
                        Debug.print(noToken.getMessage());
                    }

                }

                _certInfo = new CertInfo(certName, issuer, subject,
                        serialNumber, version, validFrom, validTo,
                        fingerPrint, trustCert, certDeleted, certTitle);
            } catch (IOException e) {
                Debug.println(e.getMessage());
            }

            _fCertInfo = true;
        }

    }

    void parseCertificateInstInfo(String response) {
        if ((response.indexOf(startCertInstInfo) != -1) ||
                (response.indexOf(startCRLCertInstInfo) != -1)) {
            _certInstInfo = new Hashtable();

            try {
                BufferedReader stream =
                        new BufferedReader(new StringReader(response));
                String line;

                while (! (((line =
                        stream.readLine()).equals(startCertInstInfo))
                        || (line.equals(startCRLCertInstInfo)))) {
                }


                while (! ((line =
                        stream.readLine()).equals(endCertInstInfo)) &&
                        !(line.equals(endCRLCertInstInfo))) {
                    StringTokenizer token =
                            new StringTokenizer(line, "=\n", false);
                    Debug.print(line);
                    try {
                        String key = token.nextToken();
                        String val = token.nextToken();
                        _certInstInfo.put(key, val);
                    } catch (NoSuchElementException noToken) {
                        Debug.print(noToken.getMessage());
                    }
                }
            } catch (IOException e) {
                Debug.println(e.getMessage());
            }
            _fCertInstInfo = true;
        }
    }

    public static String urlDecode(String urlString) {
        ByteArrayOutputStream out =
                new ByteArrayOutputStream(urlString.length());

        for (int i = 0; i < urlString.length(); i++) {
            int c = (int) urlString.charAt(i);
            if (c == '+') {
                out.write(' ');
            } else if (c == '%') {
                int c1 = Character.digit(urlString.charAt(++i), 16);
                int c2 = Character.digit(urlString.charAt(++i), 16);
                out.write((char)(c1 * 16 + c2));
            } else {
                out.write(c);
            }
        }

        return out.toString();
    }

    Vector familyList;
    public Vector parseFamilyList(String response) {
        familyList = new Vector();
        _fsecurityFortezza = false;
        _fsecurityDomestic = false;
        try {
            BufferedReader stream =
                    new BufferedReader(new StringReader(response));
            String line = null;

            while (!(((line = stream.readLine()).startsWith("NULL")))) {
                String cipherName = line.substring(0, line.indexOf("="));

                StringTokenizer st = new StringTokenizer(
                        line.substring(line.indexOf("=") + 1,
                        line.length()), ",\n", false);
                Vector tokenList = new Vector();
                Hashtable tokenCertList = new Hashtable();
                while (st.hasMoreTokens()) {
                    String token = st.nextToken();
                    tokenList.addElement(token);
                    tokenCertList.put(token, "");
                }

                Enumeration e = tokenList.elements();
                while (e.hasMoreElements()) {
                    String token = (String)(e.nextElement());
                    line = stream.readLine();
                    String certListString = line.substring(
                            (token + "-certs=").length(), line.length());
                    StringTokenizer certNames =
                            new StringTokenizer(certListString, ",\n",
                            false);
                    Vector certList = new Vector();
                    while (certNames.hasMoreTokens()) {
                        certList.addElement(certNames.nextToken());
                    }
                    tokenCertList.put(token, certList);
                }

                familyList.addElement(
                        new CipherEntry(cipherName, tokenCertList));
            }
            if ((line = stream.readLine()).startsWith("security")) {
                if (line.endsWith("fortezza")) {
                    _fsecurityFortezza = true;
                    _fsecurityDomestic = true;
                }
                if (line.endsWith("domestic")) {
                    _fsecurityDomestic = true;
                }
            }
        } catch (Exception e) {
            Debug.println("com.netscape.admin.certsrv.security.response:"+
                          e.toString());
        }
        return familyList;
    }


    Vector moduleList;
    public Vector parseModuleList(String response) {

        moduleList = new Vector();

        try {
            BufferedReader stream =
                    new BufferedReader(new StringReader(response));
            String line = stream.readLine();

            StringTokenizer st = new StringTokenizer(
                    line.substring(line.indexOf("=") + 1,
                    line.length()), ",\n", false);
            while (st.hasMoreTokens())
                moduleList.addElement(st.nextToken());
        } catch (Exception e) {/*System.out.println(e);*/
        }
        return moduleList;
    }


    public Response(String response) {

        //Debug.print(response);
        if (response == null) {
            return;
        }

        _response = response;

        int beginIndex = 0, endIndex = 0;
        while (true) {
            beginIndex = response.indexOf(Message.NMC_STATUS, endIndex);
            endIndex = response.indexOf(Message.NMC_STATUS,
                    beginIndex + Message.NMC_STATUS.length());
            if ((endIndex == -1) && (beginIndex == -1)) {
                break;
            }
            if (endIndex != -1) {
                _messages.addElement( new Message( KeyCertUtility.replace(
                        response.substring(beginIndex, endIndex), "\r",
                        "")));
            } else {
                _messages.addElement( new Message( KeyCertUtility.replace(
                        response.substring(beginIndex,
                        response.length()), "\r", "")));
                break;
            }
        }
    }

    public Vector getFamilyList() {
        return parseFamilyList(_response);
    }

    public Vector getModuleList() {
        return parseModuleList(_response);
    }

    public boolean isSecurityDomestic() {
        return _fsecurityDomestic;
    }

    public boolean isSecurityFortezza() {
        return _fsecurityFortezza;
    }
    public boolean hasCert() {
        parseCertificate(_response);
        return _fCert;
    }
    public boolean hasMessage() {
        return (_messages.size() > 0);
    }

    public boolean hasCertList() {
        parseCertificateList(_response);
        return _fCertList;
    }
    public boolean hasCertInfo() {
        parseCertificateInfo(_response);
        return _fCertInfo;
    }
    public boolean hasCertInstInfo() {
        parseCertificateInstInfo(_response);
        return _fCertInstInfo;
    }
    public String getCert() {
        return _fCert ? _cert : "";
    }
    public Vector getMessages() {
        return _messages;
    }
    public Vector getCertList() {
        return _fCertList ? _certList : (new Vector());
    }
    public CertInfo getCertInfo() {
        return _certInfo;
    }
    public Hashtable getCertInstInfo() {
        return _certInstInfo;
    }
    public String getServerResponse() {
        return _response;
    }
}
