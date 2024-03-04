/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.comm;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.lang.reflect.Method;
import java.net.Socket;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Enumeration;
import java.util.Hashtable;

import com.netscape.management.client.console.VersionInfo;
import com.netscape.management.client.preferences.Preferences;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.IProgressListener;
import com.netscape.management.client.util.Permissions;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.util.URLByteEncoder;


/**
 * A HTTP protocol handler.
 * The HttpChannel is an implementation of the CommChannel interface
 * for HTTP protocol connections.
 *
 */
public class HttpChannel implements Runnable, CommChannel {
    final static protected String HTTP_GET = "GET";
    final static protected String HTTP_POST = "POST";
    final static protected String http_prot = "HTTP/1.0"; // 397528: using 1.0 prevents ES from using chunked data
    final static protected String newline = "\r\n";

    final static protected int defaultExpectedLineLength = 128;

    public static ResourceSet _resource_theme = new ResourceSet("com.netscape.management.client.theme.theme");

    static protected int defaultBufferLength = 512;

    protected Thread thread = null;
    protected URL tid = null;
    protected HttpManager manager = null;
    protected String language = null;
    protected String name = null;
    protected boolean sendUTF8 = false;
    protected String _adminVersion;

    protected Socket socket = null;
    protected BufferedOutputStream bos = null;
    protected BufferedInputStream bis = null;

    protected boolean dead = false;
    protected boolean busy = false;

    protected HttpChannel(Object _tid, String _name, HttpManager _manager) {
        tid = (URL)_tid;
        manager = _manager;
        language = CommManager.getLanguage();
        name = tid.toString() + "[" + _name + "]";
        sendUTF8 = CommManager.getSendUTF8();
    }

    public void open() throws IOException {
        open(null);
    };

    public void open(Preferences pref) throws IOException {
        Method m = Permissions.getEnablePrivilegeMethod();

        if (m != null) {
            Object[] args = new Object[1];

            args[0] = "UniversalConnect";
            try {
                m.invoke(null, args);
            } catch (Exception e) {
                System.err.println(
                        "HttpChannel:open():unable to grant UniversalConnect:" + e);
            }
        }

        socket = new Socket(getHost(), getPort());
        bos = new BufferedOutputStream(socket.getOutputStream(),
                defaultBufferLength);
        bis = new BufferedInputStream(socket.getInputStream(),
                defaultBufferLength);

        Debug.println(name + " open> Ready");

        thread = new Thread(this, tid.toString());
        thread.start();
    }

    public void close() throws IOException {
        dead = true;

        if (bos != null) {
            bos.close();
            bos = null;
        }

        if (bis != null) {
            bis.close();
            bis = null;
        }

        if (socket != null) {
            socket.close();
            socket = null;
            Debug.println(name + " close> Closed");
        }

        if (thread != null) {
            thread = null;
        }
    }

    public boolean ready() {
        return (thread != null && !dead && !busy);
    }
    public Object targetID() {
        return tid;
    }
    public String toString() {
        return name;
    }

    protected static void setBufferSize(int size) {
        defaultBufferLength = size;
    }

    public void run() {
        boolean reuseChannel = false;
        while (!dead) {
            CommRecord cr = null;

            busy = false;

            try {
                cr = manager.next(this);
            } catch (IOException e) {
                Debug.println(name + " error> " + e);
                kill();
                break;
            }

            if (cr == null) {
                kill();
                break;
            }

            cr.setChannel(this);

            busy = true;

            Debug.println(name + " accept> " + cr.getTarget());

            if (cr.getStatus().equals(CommRecord.ERROR)) {
                Debug.println(name + "error> CommRecord Status: " +
                        CommRecord.ERROR);
                continue;
            }

            CommClient cc = cr.getClient();

            try {
                if (reuseChannel) {
                    if (!isConnected()) {
                        Debug.println(name + " test> connection is lost -- open new channel");
                        retry(cr);
                        kill();
                        return;
                    }
                    else {
                        Debug.println(name + " test> connection is still there");
                    }
                }
                reuseChannel = true;
                invoke(cr);
            } catch (HttpException he) {
                Debug.println(name + " error> " + he);
                cr.setStatus(CommRecord.ERROR);
                cc.errorHandler(he, cr);
                kill();
            }
            catch (InterruptedIOException iioe) {
                Debug.println(name + " error> " + iioe);
                cr.setStatus(CommRecord.ERROR);
                cc.errorHandler(iioe, cr);
                kill();
            }
            catch (EOFException ioe) {
                Debug.println(name + " error> " + ioe);
                cr.setStatus(CommRecord.ERROR);
                cc.errorHandler(ioe, cr);
                kill();
            }
            catch (IOException ioe) {
                // HTTP/1.0 connections are not persistent; attempts to use them for a second
                // request will return an IOException, as they have closed. To
                // avoid confusion, I am suppressing the error message (too many people
                // were reporting bugs when they saw this message). This means that a true
                // error will not reported here unless tracing is on. Unfortunately, there is
                // no way to determine if a socket has closed, other than to write to it and
                // catch the IOException. And, not all servers seem to correctly indicate that
                // they are HTTP/1.0, so we can't key off the response header...
                Debug.println(name + " error> " + ioe);
                retry(cr);
                kill();
            }

            finally { if (Debug.httpTraceEnabled()) {
                    Debug.println(Debug.TYPE_HTTP, "Done!");
                }
            }
        }
    }

    private void retry(CommRecord cr) {
        try {
            manager.retry(cr);
        } catch (IOException ioe) {
            Debug.println(name + " error> " + ioe);
        }
    }

    private void kill() {
        try {
            manager.closeChannel(this);
        } catch (IOException ie) {
            Debug.println(name + " error> " + ie);
        }
    }

    private void invoke(CommRecord cr) throws IOException, HttpException {
        boolean retryRequest = false;
        boolean closeChannel = false;

        String file = ((URL)(cr.getTarget())).getFile();
        InputStream data = cr.getData();

        if (!sendUTF8) {
            writeLine(((data == null) ? HTTP_GET : HTTP_POST) + " " +
                    file + " " + http_prot);
        } else {
            write(((data == null) ? HTTP_GET : HTTP_POST) + " ");
            write(file.getBytes("UTF8"));
            writeLine(" " + http_prot);
        }

        writeLine("Host: " + getHost() + ":" + getPort());
        writeLine("Connection: Keep-Alive");
        try {
            String consoleVersion = VersionInfo.getVersionNumber();
            writeLine("User-Agent: "+
                _resource_theme.getString("console","useragent")+ "/" + consoleVersion);
        } catch (Exception e) {
            writeLine("User-Agent:"+
                _resource_theme.getString("console","useragent")+ "/");
        }
        writeLine("Accept-Language: " + language);

        CommClient cc = cr.getClient();
        Object auth = cr.getAuthObj();
        String[] hdrs = (String[])(cr.getChannelArg());

        if (auth != null) {
            // auth is realm from previously bounced request

            String user = cc.username(auth, cr);
            String pw = cc.password(auth, cr);

            user = (user != null) ? user : "";
            pw = (pw != null) ? pw : "";

            if (!sendUTF8) {
                writeLine("Authorization: Basic " +
                        uuencode(user + ":" + pw));
            } else {
                write("Authorization: Basic ");
                write(uuencode((user + ":" + pw).getBytes("UTF8")));
                writeLine("");
            }
        }

        if (hdrs != null) {
            for (int i = 0 ; i < hdrs.length ; i++)
                writeLine(hdrs[i]);
        }

        if (data != null) {
            int dlen = cr.getDataLength();
            writeLine("Content-Length:" + dlen);
            writeLine("Content-Type: application/x-www-form-urlencoded");
            writeLine("Content-Transfer-Encoding: 7bit");
            writeLine("");
            write(data, dlen);
        } else
            writeLine("");

        cr.setStatus(CommRecord.SENT);

        socket.setSoTimeout(manager.getResponseTimeout());
        String line = readLine();

        int i = line.indexOf(' ');
        int status =
                Integer.parseInt(line.substring(i + 1, i + 1 + 3)); // status len = 3
                String protocol = line.substring(0, i);

        switch (status) {
        case HttpManager.HTTP_OK:
        case HttpManager.HTTP_MOVEDTEMP:
        case HttpManager.HTTP_MOVEDPERM:
            break;

        case HttpManager.HTTP_AUTHREQ:
            if (auth == null)
                break;
            // failed attempt
            throw new HttpException(((URL)(cr.getTarget())), line, status);

        default:
            throw new HttpException(((URL)(cr.getTarget())), line, status);
        }

        int contentlen = -1;

        auth = null;

        while (true) {
            line = readLine();

            if (line.regionMatches(true, 0, "Content-length", 0, 14)) {
                contentlen = Integer.parseInt(
                        line.substring(line.indexOf(':') + 2));
                continue;
            }

            if (line.regionMatches(true, 0, "WWW-authenticate", 0, 16)) {
                int ii = line.indexOf('=');
                if (ii == -1)
                    throw new HttpException(((URL)(cr.getTarget())),
                            line, -1);
                auth = line.substring(ii + 1);
                retryRequest = true;
                continue;
            }


            // A custom header, "Admin-Server", used by the AS5.0 and higher
            // Introduced to be able to specify the AS version independently
            // of the HTTP server version
            if (line.regionMatches(true, 0, "Admin-Server:", 0, 13)) {
            int ii = line.indexOf('/');
                if (ii == -1) {
                    Debug.println("HttpChannel.invoke: no version in " +
                                  line);
                } else {
                    _adminVersion = line.substring(ii + 1);
                    Debug.println("HttpChannel.invoke: admin version = " +
                                  _adminVersion);
                }

                continue;
            }

            if (line.regionMatches(true, 0, "Server:", 0, 7) && _adminVersion == null) {
                int ii = line.indexOf('/');
                if (ii == -1) {
                    Debug.println("HttpChannel.invoke: no version in " +
                                  line);
                } else {
                    _adminVersion = line.substring(ii + 1);
                    Debug.println("HttpChannel.invoke: admin version = " +
                                  _adminVersion);
                }

                continue;
            }

            if (line.regionMatches(true, 0, "Location:", 0, 9) &&
                    ((status == HttpManager.HTTP_MOVEDTEMP) ||
                    (status == HttpManager.HTTP_MOVEDPERM))) {
                cr.setTarget(
                        new URL(line.substring(line.indexOf(':') + 2)))
                        ; // redirect target for retry
                        retryRequest = true;
                continue;
            }

            if (line.trim().length() == 0)
                break;
        }

        boolean async = cr.getAsyncResponseMode();

        if (contentlen == -1) {
            // No valid Content-Length: Header, so read until EOF

            AsyncByteArrayInputStream response =
                    new AsyncByteArrayInputStream();

            if (!retryRequest && async)
                new ClientThread(cr, response).start();

            Debug.println(name + " recv> Reading unknown length bytes...");

            int c;
            //hack to ignore read errors.
            try {
                while (((c = bis.read()) != -1)) {// -1: EOF
                    response.write(c);
                }
            } catch (Exception e) {}
            response.setEOF();
            cr.setStatus(CommRecord.COMPLETE);

            Debug.println(name + " recv> " + response.size() + " bytes read");

            if (!retryRequest && !async)
                new ClientThread(cr, response).start();

            closeChannel = true; // we've read the socket to EOF.
        } else if (contentlen >= 0) {
            IProgressListener progressListener = null;
            if (cr.getClient() instanceof CommClient2) {
                final CommRecord fcr = cr;
                progressListener = new IProgressListener() {
                            public void progressUpdate(String text,
                                    int total, int done) {
                                ((CommClient2) fcr.getClient()).
                                        progressUpdate(
                                        fcr.target.toString(), total, done);
                            }
                        };
            }
            AsyncByteArrayInputStream response =
                    new AsyncByteArrayInputStream(contentlen > 0 ?
                    contentlen : 1, progressListener);

            if (!retryRequest && async)
                new ClientThread(cr, response).start();

            Debug.println(name + " recv> Reading " + contentlen + " bytes...");

            if (contentlen > 0)
                response.write(bis, contentlen);
            response.setEOF();
            cr.setStatus(CommRecord.COMPLETE);

            Debug.println(name + " recv> " + response.available() + " bytes read");

            if (!retryRequest && !async)
                new ClientThread(cr, response).start();

            if (protocol.compareTo(http_prot) < 0)
                closeChannel = true; // Prior to HTTP/1.1, connections were not persistent
        }

        if (auth != null) {
            cr.setAuthObj(auth);
        }

        if (retryRequest) {
            retry(cr);
        }
        if (closeChannel) {
            kill();
        }
        return; // transaction successfully completed
    }

    private void write(String s) throws IOException {
        byte[] b = s.getBytes();
        bos.write(b);
        bos.flush();

        Debug.println(name + " send> " + s + " \\");
    }

    private void write(byte[] b) throws IOException {
        bos.write(b);
        bos.flush();

        Debug.println(name + " send> " + new String(b) + " \\");
    }

    private void writeLine(String s) throws IOException {
        byte[] b = (s + newline).getBytes();
        bos.write(b);
        bos.flush();

        Debug.println(name + " send> " + s);
    }

    private void write(InputStream r, int len) throws IOException {
        Debug.println(name + " send> Writing " + len + " bytes...");

        byte[] buf = new byte[len];
        r.read(buf);
        bos.write(buf);
        bos.flush();

        Debug.println(name + " send> " + len + " bytes written");
    }

    protected String readLine() throws IOException {
        int c;
        int size = defaultBufferLength;
        byte b[] = new byte[size];
        int len = 0;
        boolean eoln = false;

        try {
            while (!eoln) {
                switch (c = bis.read()) {
                default:
                    //tmp fix for https...it's getting 0 byte.
                    try {
                        if (bis.available() == 0) {
                            continue;
                        }
                    } catch (Exception e) {}
                    if (len == size) {
                        // resize
                        byte[] tmp = new byte[size + defaultBufferLength];
                        System.arraycopy(b, 0, tmp, 0, size);
                        size += defaultBufferLength;
                        b = tmp;
                    }
                    b[len++] = (byte) c;
                    break;

                case '\n':
                    eoln = true;
                    break;
                case - 1:
                     throw new EOFException("Connection lost");


                case '\r':
                    eoln = true;
                    int c2 = bis.read();
                    if (c2 != '\n')
                        System.err.println("HttpChannel:readLine():carriage return not followed by newline in stream.");
                    break;
                }
            }

            String s = new String(b, 0, len);
            Debug.println(name + " recv> " + s);
            return s;
        } catch (InterruptedIOException ie) {
            Debug.println(name + " recv> interrupted");
            throw new InterruptedIOException("HTTP response timeout");
        }
    }

    /**
     * Check if the line is still availbale when reusing an existing channel
     * to send a new request; Keep-Alive flag might not have been honored.
     * If  for some reason the server has dropped the connection, read()
     * will return -1 (EOF), otherwise we will timeout after 100 ms.
     * Calling read() without evaluating the returned content is safe
     * here, as no request has been sent yet so we should either timeout or
     * get EOF.
     * @return flag if the line to the server is still opened
     */
    private boolean isConnected() throws IOException {
        int origTimeout = socket.getSoTimeout();
        try {
            final int EOF = -1;
            // wait in read no more than 100 ms
            socket.setSoTimeout(100);
            int c = bis.read();
            if (c == EOF) {
                // The server has disconnected
                return false;
            }
            // Should never get here, force reconnect
            Debug.println(0, "Unexpected data received 0x" + Integer.toHexString(c));
            throw new IOException();
        }
        catch (InterruptedIOException ex) {
            ; //Read has timed out, connection is there, continue
        }
        finally {
            socket.setSoTimeout(origTimeout);
        }
        return true;
    }

    /**
      * Translates a byte[] into <code>x-www-form-urlencoded</code> format.
      *
      * @param   array   <code>byte[]</code> to be translated.
      * @return  a ByteArrayInputStream to the translated <code>byte[]</code>.
      */
    public static ByteArrayInputStream encode(byte[] array) {
        if (array == null)
            return (null);

        return new ByteArrayInputStream(
                _encode(new String(array)).getBytes());
    }

    /**
      * Translates a hashtable into <code>x-www-form-urlencoded</code> format.
      *
      * @param   args   <code>Hashtable</code> containing name/value pairs to be translated.
      * @return  a ByteArrayInputStream to the translated <code>Hashtable</code> contents.
      */
    public static ByteArrayInputStream encode(Hashtable args) {
        if ((args == null) || (args.size() == 0))
            return (null);

        String p = "";
        Enumeration e = args.keys();

        while (e.hasMoreElements()) {
            String name = (String) e.nextElement();
            String value = (String)(args.get(name));

            p += name + "=" + URLByteEncoder.encodeUTF8(value) +
                    (e.hasMoreElements() ? "&":"");
        }

        return new ByteArrayInputStream(p.getBytes());
    }

    /**
      * Translates a string into <code>x-www-form-urlencoded</code> format.
      *
      * @param   s   <code>String</code> to be translated.
      * @return  the translated <code>String</code>.
      * @deprecated use URLEncoder.encode(String) instead
      */
    @Deprecated
    public static String _encode(String s) {
        return URLEncoder.encode(s);
    }

    private static final byte[] cipherset = {
    (byte)'A',(byte)'B',(byte)'C',(byte)'D',(byte)'E',(byte)'F',(byte)'G',
    (byte)'H',(byte)'I',(byte)'J',(byte)'K',(byte)'L',(byte)'M',(byte)'N',
    (byte)'O',(byte)'P',(byte)'Q',(byte)'R',(byte)'S',(byte)'T',(byte)'U',
    (byte)'V',(byte)'W',(byte)'X',(byte)'Y',(byte)'Z',
    (byte)'a',(byte)'b',(byte)'c',(byte)'d',(byte)'e',(byte)'f',(byte)'g',
    (byte)'h',(byte)'i',(byte)'j',(byte)'k',(byte)'l',(byte)'m',(byte)'n',
    (byte)'o',(byte)'p',(byte)'q',(byte)'r',(byte)'s',(byte)'t',(byte)'u',
    (byte)'v',(byte)'w',(byte)'x',(byte)'y',(byte)'z',
    (byte)'0',(byte)'1',(byte)'2',(byte)'3',(byte)'4',(byte)'5',(byte)'6',
    (byte)'7',(byte)'8',(byte)'9',(byte)'+',(byte)'/' };

    public static String uuencode(String s) {
        return new String(uuencode(s.getBytes()));
    }

    public static byte[] uuencode(byte[] b) {
        byte[] src, dst;

        int len = b.length;
        int mod = len % 3;

        // zero pad source bytes to an integral multiple of 3
        src = new byte[len + (mod == 0 ? 0 : 3 - mod)];
        dst = new byte[src.length * 4 / 3];
        System.arraycopy(b, 0, src, 0, len);

        int si = 0;
        int di = 0;

        for (; si < src.length ;) {
            byte b0 = src[si++];
            byte b1 = src[si++];
            byte b2 = src[si++];

            dst[di++] = cipherset[(b0 >> 2) & 0x3F];
            dst[di++] = cipherset[((b0 & 0x03) << 4) | ((b1 & 0xF0) >> 4)];
            dst[di++] = cipherset[((b1 & 0x0F) << 2) | ((b2 & 0xC0) >> 6)];
            dst[di++] = cipherset[(b2 & 0x3F)];
        }

        // pad bits in the output must be converted to '='
        switch (mod) {
        case 0:
            break;
        case 1:
            dst[--di] = dst[--di] = (byte)'=';
            break;
        case 2:
            dst[--di] = (byte)'=';
            break;
        }

        return dst;
    }

    protected String getHost() {
        return tid.getHost();
    }

    protected int getPort() {
        return tid.getPort();
    }

    protected String getProtocol() {
        return tid.getProtocol();
    }

    /**
     * Get the version of the server for the latest request
     *
     * @return The version of the Admin Server in the latest request, e.g. "4.5"
     */
    public String getAdminVersion() {
        return _adminVersion;
    }
}
