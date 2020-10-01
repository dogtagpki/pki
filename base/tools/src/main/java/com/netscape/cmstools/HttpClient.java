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
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.Socket;
import java.util.Properties;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.InitializationValues;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.netscape.security.util.Utils;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLHandshakeCompletedListener;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.crypto.CryptoUtil;

/**
 * This class implements a CMC Enroll client for testing.
 *
 * @version $Revision$, $Date$
 */
public class HttpClient {
    private String _host = null;
    private int _port = 0;
    private boolean _secure = false;

    public static final int ARGC = 1;
    public static final int MAX_HTTP_RESPONSE_HEADER_LINES = 56;

    public HttpClient(String host, int port, String secure)
            throws Exception {
        _host = host;
        _port = port;
        if (secure.equals("true"))
            _secure = true;
    }

    public static byte[] getBytesFromFile(String filename) throws IOException {
        File file = new File(filename);
        FileInputStream is = null;

        long length = file.length();

        if (length > Integer.MAX_VALUE) {
            throw new IOException("Input file " + filename +
                    " is too large. Must be smaller than " + Integer.MAX_VALUE);
        }

        byte[] bytes = new byte[(int) length];

        int offset = 0;
        int numRead = 0;
        try {
            is = new FileInputStream(file);
            while (offset < bytes.length
                    && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
                offset += numRead;
            }
        } finally {
            if (is != null) {
                is.close();
            }
        }
        if (offset < bytes.length) {
            throw new IOException("Could not completely read file " + filename);
        }
        return bytes;
    }

    public void send(String ifilename, String ofilename, String tokenName, String dbdir,
            String nickname, String password, String servlet, String clientmode,
            int numHeaderLines)
            throws Exception {
        DataOutputStream dos = null;
        InputStream is = null;
        PrintStream ps = null;
        ByteArrayOutputStream bs = null;
        SSLSocket sslSocket = null;
        Socket socket = null;
        try {
            byte[] b = getBytesFromFile(ifilename);

            System.out.println("Total number of bytes read = " + b.length);
            if (_secure) {
                InitializationValues vals =
                        new InitializationValues(dbdir, "", "", "secmod.db");
                CryptoManager.initialize(vals);
                CryptoManager cm = CryptoManager.getInstance();
                CryptoToken token = CryptoUtil.getKeyStorageToken(tokenName);
                if (CryptoUtil.isInternalToken(tokenName)) {
                    tokenName = CryptoUtil.INTERNAL_TOKEN_NAME;
                }
                cm.setThreadToken(token);
                Password pass = new Password(password.toCharArray());
                try {
                    token.login(pass);
                } finally {
                    pass.clear();
                }

                SSLHandshakeCompletedListener listener = new ClientHandshakeCB(this);

                sslSocket = new SSLSocket(_host, _port);
                sslSocket.addHandshakeCompletedListener(listener);
                sslSocket.enablePostHandshakeAuth(true);

                CryptoToken tt = cm.getThreadToken();
                System.out.println("after SSLSocket created, thread token is "+ tt.getName());

                if (clientmode != null && clientmode.equals("true")) {
                    StringBuffer certname = new StringBuffer();
                    if (!token.equals(cm.getInternalKeyStorageToken())) {
                        certname.append(tokenName);
                        certname.append(":");
                    }
                    certname.append(nickname);

                    X509Certificate cert =
                        cm.findCertByNickname(certname.toString());

                    if (cert == null)
                        System.out.println("client cert is null");
                    else
                        System.out.println("client cert is not null");
                    sslSocket.setUseClientMode(true);
                    sslSocket.setClientCertNickname(nickname);
                }

                sslSocket.forceHandshake();
                dos = new DataOutputStream(sslSocket.getOutputStream());
                is = sslSocket.getInputStream();
            } else {
                socket = new Socket(_host, _port);
                dos = new DataOutputStream(socket.getOutputStream());
                is = socket.getInputStream();
            }

            // send request
            if (servlet == null) {
                System.out.println("Missing servlet name.");
                printUsage();
            } else {
                System.out.println("writing to socket");
                String s = "POST " + servlet + " HTTP/1.0\r\n";
                dos.writeBytes(s);
            }
            dos.writeBytes("Content-length: " + b.length + "\r\n");
            dos.writeBytes("\r\n");
            dos.write(b);
            dos.flush();

            FileOutputStream fof = new FileOutputStream(ofilename);
            boolean startSaving = false;
            int sum = 0;
            boolean hack = false;
            String catchHeaders = "";
            try {
                while (true) {
                    int r = is.read();
                    if (r == -1)
                        break;
                    if (r == 10) { // line break
                        sum++;
                    }

                    // catch the header lines for debugging purposes
                    if (sum < numHeaderLines) {
                        catchHeaders = catchHeaders + (char) r;
                    }
                    if (sum == 5) {
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
                }
            } catch (IOException e) {
            }
            fof.close();
            // debug
            System.out.println("\n##Response Headers begin##\n" + catchHeaders + "\n##end##\n");

            byte[] bout = getBytesFromFile(ofilename);
            System.out.println("Total number of bytes read = " + bout.length);

            bs = new ByteArrayOutputStream();
            ps = new PrintStream(bs);
            ps.print(Utils.base64encode(bout, true));
            System.out.println(bs.toString());

            System.out.println("");
            System.out.println("The response in binary format is stored in " + ofilename);
            System.out.println("");
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        } finally {
            if (is != null) {
                is.close();
            }
            if (dos != null) {
                dos.close();
            }
            if (bs != null) {
                bs.close();
            }
            if (ps != null) {
                ps.close();
            }
            if (sslSocket != null) {
                sslSocket.close();
            }
            if (socket != null) {
                socket.close();
            }
        }
    }

    static void printUsage() {
        System.out.println("");
        System.out.println("Usage: HttpClient <configuration file>");
        System.out.println("For example, HttpClient HttpClient.cfg");
        System.out.println("");
        System.out.println("The configuration file should look like as follows:");
        System.out.println("");
        System.out.println("#host: host name for the http server");
        System.out.println("host=host.example.com");
        System.out.println("");
        System.out.println("#port: port number");
        System.out.println("port=8443");
        System.out.println("");
        System.out.println("#secure: true for secure connection, false for nonsecure connection");
        System.out.println("secure=false");
        System.out.println("");
        System.out.println("#input: full path for the enrollment request, the content must be in binary format");
        System.out.println("input=~/cmcReqCRMFBin");
        System.out.println("");
        System.out.println("#output: full path for the response in binary format");
        System.out.println("#output could be parsed by running CMCResponse");
        System.out.println("output=~/cmcResp");
        System.out.println("");
        System.out.println("#dbdir: directory for NSS certificate/key databases");
        System.out.println("#This parameter will be ignored if secure=false");
        System.out.println("dbdir=/.dogtag/nssdb");
        System.out.println("");
        System.out.println("#password: password for NSS database");
        System.out.println("#This parameter will be ignored if secure=false and clientmode=false");
        System.out.println("password=");
        System.out.println("");
        System.out.println("#tokenname: name of token where SSL client authentication cert for nickname can be found (default is internal)");
        System.out.println("#This parameter will be ignored if secure=false");
        System.out.println("tokenname=internal");
        System.out.println("");
        System.out.println("#clientmode: true for client authentication, false for no client authentication");
        System.out.println("#This parameter will be ignored if secure=false");
        System.out.println("clientmode=false");
        System.out.println("");
        System.out.println("#nickname: nickname for client certificate");
        System.out.println("#This parameter will be ignored if clientmode=false");
        System.out.println("nickname=");
        System.out.println("");
        System.out.println("#servlet: target URL");
        System.out.println("#This parameter may include query parameters;");
        System.out.println("#  - reminder: profileId should be a profile that matches");
        System.out.println("#    the intended certificate; for certificates intended");
        System.out.println("#    for SSL (client or server), profiles should match");
        System.out.println("#    the key type (RSA or EC) of the keys generated for CSR;");
        System.out.println("servlet=/ca/ee/ca/profileSubmitCMCFull?profileId=caFullCMCUserCert");
        System.out.println("");
        System.exit(0);
    }

    public static void main(String args[]) {

        System.out.println("");

        // Check that the correct # of arguments were submitted to the program
        if (args.length != (ARGC)) {
            System.out.println("Wrong number of parameters:" + args.length);
            printUsage();
        }

        String configFile = args[0];
        BufferedReader reader = null;
        try {
            reader = new BufferedReader(new InputStreamReader(
                            new BufferedInputStream(
                                    new FileInputStream(configFile))));
        } catch (FileNotFoundException e) {
            System.out.println("HttpClient:  can't find configuration file: " + configFile);
            printUsage();
            System.exit(1);
        } catch (Exception e) {
            e.printStackTrace();
            printUsage();
            return;
        }

        Properties config = new Properties();
        try {
            config.load(reader);

        } catch (Exception e) {
            e.printStackTrace();
            printUsage();
        }

        String host = config.getProperty("host");
        String portstr = config.getProperty("port");
        String secure = config.getProperty("secure");
        String tokenName = config.getProperty("tokenname");
        String dbdir = config.getProperty("dbdir");
        String nickname = config.getProperty("nickname");
        String password = config.getProperty("password");
        String ofilename = config.getProperty("output");
        String ifilename = config.getProperty("input");
        String clientmode = config.getProperty("clientmode");
        String servlet = config.getProperty("servlet");

        // unadvertised parameter to tell HttpClient how many header lines
        // to skip
        String numHeaderLinesStr = config.getProperty("numHeaderLines");

        if (host == null) {
            System.out.println("Missing host name.");
            printUsage();
        }

        if (portstr == null) {
            System.out.println("Missing port number.");
            printUsage();
        }

        if (servlet == null) {
            System.out.println("Missing servlet name.");
            printUsage();
        }

        if (ifilename == null) {
            System.out.println("Missing input filename for the enrollment request.");
            printUsage();
        }

        if (ofilename == null) {
            System.out.println("Missing output filename for the response.");
            printUsage();
        }

        int port = Integer.parseInt(portstr);

        if (secure != null && secure.equals("true")) {
            if (dbdir == null) {
                System.out.println("Missing directory name for the cert7.db.");
                printUsage();
            }

            if (clientmode != null && clientmode.equals("true")) {
                if (password == null) {
                    System.out.println("Missing password for the cert7.db.");
                    printUsage();
                }
                if (nickname == null) {
                    System.out.println("Missing nickname for the client certificate");
                    printUsage();
                }
            }
        }

        /*
         * numHeaderLines is the number of lines in the header;
         * By default it is 5 (in earlier version it was 6);
         * One should not need to set this, but we provide this
         * parameter in case it gets changed
         */
        int numHeaderLines = 5;
        if (numHeaderLinesStr != null) {
            numHeaderLines = Integer.parseInt(numHeaderLinesStr);
            if (numHeaderLines < 1 || numHeaderLines > MAX_HTTP_RESPONSE_HEADER_LINES) {
                System.out.println("numHeaderLines " + numHeaderLines + " out of range: 1 - 56");
                System.exit(1);
            }
        }

        try {
            HttpClient client =
                    new HttpClient(host, port, secure);
            client.send(ifilename, ofilename, tokenName,  dbdir, nickname, password, servlet, clientmode, numHeaderLines);
        } catch (Exception e) {
            System.out.println("Error: " + e.toString());
        }
    }

    static class ClientHandshakeCB implements SSLHandshakeCompletedListener {
        Object sc;

        public ClientHandshakeCB(Object sc) {
            this.sc = sc;
        }

        public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
            System.out.println("handshake happened");
        }
    }
}
