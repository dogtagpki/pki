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
package com.netscape.cmstools;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.MessageDigest;

import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509Key;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.asn1.INTEGER;
import org.mozilla.jss.asn1.NULL;
import org.mozilla.jss.asn1.OBJECT_IDENTIFIER;
import org.mozilla.jss.asn1.OCTET_STRING;
import org.mozilla.jss.asn1.SEQUENCE;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkix.primitive.AlgorithmIdentifier;

import com.netscape.cmsutil.ocsp.BasicOCSPResponse;
import com.netscape.cmsutil.ocsp.CertID;
import com.netscape.cmsutil.ocsp.CertStatus;
import com.netscape.cmsutil.ocsp.GoodInfo;
import com.netscape.cmsutil.ocsp.OCSPRequest;
import com.netscape.cmsutil.ocsp.OCSPResponse;
import com.netscape.cmsutil.ocsp.Request;
import com.netscape.cmsutil.ocsp.ResponseBytes;
import com.netscape.cmsutil.ocsp.ResponseData;
import com.netscape.cmsutil.ocsp.RevokedInfo;
import com.netscape.cmsutil.ocsp.SingleResponse;
import com.netscape.cmsutil.ocsp.TBSRequest;
import com.netscape.cmsutil.ocsp.UnknownInfo;
import com.netscape.cmsutil.util.Utils;

/**
 * This class implements a OCSP client for testing.
 * 
 * @version $Revision$, $Date$
 */
public class OCSPClient {
    private String _host = null;
    private int _port = 0;

    public OCSPClient(String host, int port, String dbdir)
            throws Exception {
        _host = host;
        _port = port;
        CryptoManager.initialize(dbdir);
    }

    public void send(String uri, String nickname, int serialno, String output)
            throws Exception {
        CryptoManager manager = CryptoManager.getInstance();
        X509Certificate caCert = manager.findCertByNickname(nickname);
        OCSPRequest request = getOCSPRequest(caCert, serialno);
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        request.encode(os);
        byte request_data[] = os.toByteArray();
        sendOCSPRequest(uri, _host, _port, request_data, output);
    }

    public void sendRequestData(String uri, String nickname, byte request_data[], String output)
            throws Exception {
        sendOCSPRequest(uri, _host, _port, request_data, output);
    }

    public OCSPRequest getOCSPRequest(X509Certificate caCert, int serialno)
             throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA");

        // calculate issuer key hash 
        X509CertImpl x509Cert = new X509CertImpl(caCert.getEncoded());
        X509Key x509key = (X509Key) x509Cert.getPublicKey();
        byte issuerKeyHash[] = md.digest(x509key.getKey());

        // calculate name hash
        X500Name name = (X500Name) x509Cert.getSubjectDN();
        byte issuerNameHash[] = md.digest(name.getEncoded());
        // constructing the OCSP request
        CertID certid = new CertID(
                new AlgorithmIdentifier(
                        new OBJECT_IDENTIFIER("1.3.14.3.2.26"), new NULL()),
                new OCTET_STRING(issuerNameHash),
                new OCTET_STRING(issuerKeyHash),
                new INTEGER(serialno));
        Request request = new Request(certid, null);
        SEQUENCE requestList = new SEQUENCE();
        requestList.addElement(request);
        TBSRequest tbsRequest = new TBSRequest(null, null, requestList, null);
        return new OCSPRequest(tbsRequest, null);
    }

    public void sendOCSPRequest(String uri, String host, int port,
               byte request_data[], String output) throws Exception {
        Socket socket = new Socket(host, port);

        // send request 
        System.out.println("URI: " + uri);

        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
        dos.writeBytes("POST " + uri + " HTTP/1.0\r\n");
        dos.writeBytes("Content-length: " + request_data.length + "\r\n");
        dos.writeBytes("\r\n");
        dos.write(request_data);
        dos.flush();

        System.out.println("Data Length: " + request_data.length);
        System.out.println("Data: " + Utils.base64encode(request_data));

        InputStream iiss = socket.getInputStream();
        FileOutputStream fof = new FileOutputStream(output);
        boolean startSaving = false;
        int sum = 0;
        boolean hack = false;
        try {
            while (true) {
                int r = iiss.read();
                if (r == -1)
                    break;
                if (r == 10) {
                    sum++;
                }
                if (sum == 6) {
                    startSaving = true;
                    continue;
                }
                if (startSaving) {
                    if (hack) {
                        fof.write(r);
                    }
                    if (hack == false) {
                        hack = true;
                    }
                }
            } // while 
        } catch (IOException e) {
        }
        fof.close();

        // parse OCSPResponse 
        BufferedInputStream fis =
                new BufferedInputStream(
                        new FileInputStream(output));
        OCSPResponse resp = (OCSPResponse)
                OCSPResponse.getTemplate().decode(fis);
        ResponseBytes bytes = resp.getResponseBytes();
        BasicOCSPResponse basic = (BasicOCSPResponse)
                BasicOCSPResponse.getTemplate().decode(
                        new ByteArrayInputStream(bytes.getResponse().toByteArray()));
        ResponseData rd = basic.getResponseData();
        for (int i = 0; i < rd.getResponseCount(); i++) {
            SingleResponse rd1 = rd.getResponseAt(i);
            System.out.println("CertID.serialNumber=" +
                    rd1.getCertID().getSerialNumber());
            CertStatus status1 = rd1.getCertStatus();
            if (status1 instanceof GoodInfo) {
                System.out.println("CertStatus=Good");
            }
            if (status1 instanceof UnknownInfo) {
                System.out.println("CertStatus=Unknown");
            }
            if (status1 instanceof RevokedInfo) {
                System.out.println("CertStatus=Revoked");
            }
        }
    }

    public static void printUsage() {
        System.out.println("Usage: OCSPClient " +
                "<host> <port> <dbdir> <nickname> <serialno_or_filename> <output> <times>");
        System.out.println("  <host>     = OCSP server hostname");
        System.out.println("  <port>     = OCSP server port number");
        System.out.println("  <dbdir>    = Certificate Database Directory");
        System.out.println("  <nickname> = Nickname of CA Certificate");
        System.out.println(
                "  <serialno_or_filename> = Serial Number Being Checked, Or Name of file that contains the request");
        System.out.println("  <output>   = Filename of Response in DER encoding");
        System.out.println("  <times>    = Submit Request Multiple Times");
        System.out.println("  [<uri>]    = OCSP Service URI (i.e. /ocsp/ee/ocsp)");
    }

    public static void main(String args[]) {
        if (args.length != 7 && args.length != 8) {
            System.out.println("ERROR: Invalid number of arguments - got "
                              + args.length + " expected 7!");
            for (int i = 0; i < args.length; i++) {
                System.out.println("arg[" + i + "]=" + args[i]);
            }
            printUsage();
            System.exit(0);
        }

        String host = args[0];
        int port = -1;
        try {
            port = Integer.parseInt(args[1]);
        } catch (Exception e) {
            System.out.println("Error: Invalid Port Number");
            printUsage();
            System.exit(0);
        }
        String dbdir = args[2];
        String nickname = args[3];
        int serialno = -1;
        byte data[] = null;
        try {
            serialno = Integer.parseInt(args[4]);
        } catch (Exception e) {
            try {
                System.out.println("Warning: Serial Number not found. It may be a filename.");
                /* it could be a file name */
                FileInputStream fis = new FileInputStream(args[4]);
                System.out.println("File Size: " + fis.available());
                data = new byte[fis.available()];
                fis.read(data);
            } catch (Exception e1) {
                System.out.println("Error: Invalid Serial Number or File Name");
                printUsage();
                System.exit(0);
            }
        }
        String output = args[5];
        int times = 1;
        try {
            times = Integer.parseInt(args[6]);
        } catch (Exception e) {
            System.out.println("Error: Invalid Times");
            printUsage();
            System.exit(0);
        }
        String uri = "/ocsp/ee/ocsp";
        if (args.length > 7) {
            uri = args[7];
        }
        try {
            OCSPClient client =
                    new OCSPClient(host, port, dbdir);
            for (int i = 0; i < times; i++) {
                if (data != null) {
                    client.sendRequestData(uri, nickname, data, output);
                } else {
                    client.send(uri, nickname, serialno, output);
                }
            }
            System.out.println("Success: Output " + output);
        } catch (Exception e) {
            System.out.println("Error: " + e.toString());
            printUsage();
            System.exit(0);
        }
    }
}
