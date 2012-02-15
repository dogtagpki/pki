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
import java.net.SocketException;
import java.util.StringTokenizer;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLHandshakeCompletedListener;
import org.mozilla.jss.ssl.SSLSocket;
import org.mozilla.jss.util.Password;

import com.netscape.cmsutil.util.Utils;

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
    static final int cipherSuites[] = {
            SSLSocket.SSL3_RSA_WITH_RC4_128_MD5,
            SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA,
            SSLSocket.SSL3_RSA_WITH_DES_CBC_SHA,
            SSLSocket.SSL3_RSA_EXPORT_WITH_RC4_40_MD5,
            SSLSocket.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
            SSLSocket.SSL3_RSA_WITH_NULL_MD5,
            0
    };

    public HttpClient(String host, int port, String secure)
            throws Exception {
        _host = host;
        _port = port;
        if (secure.equals("true"))
            _secure = true;
    }

    public static byte[] getBytesFromFile(String filename) throws IOException {
        File file = new File(filename);
        FileInputStream is = new FileInputStream(file);

        long length = file.length();

        if (length > Integer.MAX_VALUE) {
            throw new IOException("Input file " + filename +
                    " is too large. Must be smaller than " + Integer.MAX_VALUE);
        }

        byte[] bytes = new byte[(int) length];

        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
                && (numRead = is.read(bytes, offset, bytes.length - offset)) >= 0) {
            offset += numRead;
        }

        if (offset < bytes.length) {
            throw new IOException("Could not completely read file " + filename);
        }

        is.close();
        return bytes;
    }

    public void send(String ifilename, String ofilename, String dbdir,
            String nickname, String password, String servlet, String clientmode)
            throws Exception {
        byte[] b = getBytesFromFile(ifilename);

        System.out.println("Total number of bytes read = " + b.length);

        DataOutputStream dos = null;
        InputStream is = null;
        if (_secure) {
            try {
                CryptoManager.InitializationValues vals =
                        new CryptoManager.InitializationValues(dbdir, "", "", "secmod.db");
                CryptoManager.initialize(vals);
                SSLSocket socket = new SSLSocket(_host, _port);
                int i;

                for (i = SSLSocket.SSL2_RC4_128_WITH_MD5; i <= SSLSocket.SSL2_RC2_128_CBC_EXPORT40_WITH_MD5; ++i) {
                    try {
                        socket.setCipherPreference(i, true);
                    } catch (SocketException e) {
                    }
                }
                //skip SSL_EN_IDEA_128_EDE3_CBC_WITH_MD5
                for (i = SSLSocket.SSL2_DES_64_CBC_WITH_MD5; i <= SSLSocket.SSL2_DES_192_EDE3_CBC_WITH_MD5; ++i) {
                    try {
                        socket.setCipherPreference(i, true);
                    } catch (SocketException e) {
                    }
                }
                for (i = 0; cipherSuites[i] != 0; ++i) {
                    try {
                        socket.setCipherPreference(cipherSuites[i], true);
                    } catch (SocketException e) {
                    }
                }
                SSLHandshakeCompletedListener listener = new ClientHandshakeCB(this);
                socket.addHandshakeCompletedListener(listener);

                if (clientmode != null && clientmode.equals("true")) {
                    CryptoManager cm = CryptoManager.getInstance();
                    CryptoToken token = cm.getInternalKeyStorageToken();
                    Password pass = new Password(password.toCharArray());
                    token.login(pass);
                    CryptoStore store = token.getCryptoStore();
                    X509Certificate cert = cm.findCertByNickname(nickname);
                    if (cert == null)
                        System.out.println("client cert is null");
                    else
                        System.out.println("client cert is not null");
                    socket.setUseClientMode(true);
                    socket.setClientCertNickname(nickname);
                }

                socket.forceHandshake();
                dos = new DataOutputStream(socket.getOutputStream());
                is = socket.getInputStream();
            } catch (Exception e) {
                System.out.println("Exception: " + e.toString());
                return;
            }
        } else {
            Socket socket = new Socket(_host, _port);
            dos = new DataOutputStream(socket.getOutputStream());
            is = socket.getInputStream();
        }

        // send request 
        if (servlet == null) {
            System.out.println("Missing servlet name.");
            printUsage();
        } else {
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
        try {
            while (true) {
                int r = is.read();
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
            }
        } catch (IOException e) {
        }
        fof.close();

        byte[] bout = getBytesFromFile(ofilename);
        System.out.println("Total number of bytes read = " + bout.length);

        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bs);
        ps.print(Utils.base64encode(bout));
        System.out.println(bs.toString());

        System.out.println("");
        System.out.println("The response in binary format is stored in " + ofilename);
        System.out.println("");
    }

    static void printUsage() {
        System.out.println("");
        System.out.println("Usage: HttpClient <configuration file>");
        System.out.println("For example, HttpClient HttpClient.cfg");
        System.out.println("");
        System.out.println("The configuration file should look like as follows:");
        System.out.println("");
        System.out.println("#host: host name for the http server");
        System.out.println("host=host1.a.com");
        System.out.println("");
        System.out.println("#port: port number");
        System.out.println("port=1025");
        System.out.println("");
        System.out.println("#secure: true for secure connection, false for nonsecure connection");
        System.out.println("secure=false");
        System.out.println("");
        System.out.println("#input: full path for the enrollment request, the content must be in binary format");
        System.out.println("input=/u/doc/cmcReqCRMFBin");
        System.out.println("");
        System.out.println("#output: full path for the response in binary format");
        System.out.println("output=/u/doc/cmcResp");
        System.out.println("");
        System.out.println("#dbdir: directory for cert8.db, key3.db and secmod.db");
        System.out.println("#This parameter will be ignored if secure=false");
        System.out.println("dbdir=/u/smith/.netscape");
        System.out.println("");
        System.out.println("#clientmode: true for client authentication, false for no client authentication");
        System.out.println("#This parameter will be ignored if secure=false");
        System.out.println("clientmode=false");
        System.out.println("");
        System.out.println("#password: password for cert8.db");
        System.out.println("#This parameter will be ignored if secure=false and clientauth=false");
        System.out.println("password=");
        System.out.println("");
        System.out.println("#nickname: nickname for client certificate");
        System.out.println("#This parameter will be ignored if clientmode=false");
        System.out.println("nickname=");
        System.out.println("");
        System.out.println("#servlet: servlet name");
        System.out.println("servlet=/ca/profileSubmitCMCFull");
        System.out.println("");
        System.exit(0);
    }

    public static void main(String args[]) {
        String host = null, portstr = null, secure = null, dbdir = null, nickname = null;
        String password = null, ofilename = null, ifilename = null;
        String servlet = null;
        String clientmode = null;

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

        try {
            String str = "";
            while ((str = reader.readLine()) != null) {
                str = str.trim();
                if (!str.startsWith("#") && str.length() > 0) {
                    StringTokenizer tokenizer = new StringTokenizer(str, "=");
                    if (tokenizer.hasMoreTokens()) {
                        String name = tokenizer.nextToken();
                        String val = null;
                        if (tokenizer.countTokens() > 0)
                            val = tokenizer.nextToken();
                        if (name.equals("host")) {
                            host = val;
                        } else if (name.equals("port")) {
                            portstr = val;
                        } else if (name.equals("secure")) {
                            secure = val;
                        } else if (name.equals("dbdir")) {
                            dbdir = val;
                        } else if (name.equals("nickname")) {
                            nickname = val;
                        } else if (name.equals("password")) {
                            password = val;
                        } else if (name.equals("output")) {
                            ofilename = val;
                        } else if (name.equals("input")) {
                            ifilename = val;
                        } else if (name.equals("clientmode")) {
                            clientmode = val;
                        } else if (name.equals("servlet")) {
                            servlet = val;
                        }
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            printUsage();
        }

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

        try {
            HttpClient client =
                    new HttpClient(host, port, secure);
            client.send(ifilename, ofilename, dbdir, nickname, password, servlet, clientmode);
        } catch (Exception e) {
            System.out.println("Error: " + e.toString());
        }
    }

    class ClientHandshakeCB implements SSLHandshakeCompletedListener {
        Object sc;

        public ClientHandshakeCB(Object sc) {
            this.sc = sc;
        }

        public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
            System.out.println("handshake happened");
        }
    }
}
