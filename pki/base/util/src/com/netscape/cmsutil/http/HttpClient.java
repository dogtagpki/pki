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
package com.netscape.cmsutil.http;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.Socket;

import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;

import com.netscape.cmsutil.net.ISocketFactory;

/**
 * basic http client.
 * not optimized for performance.
 * handles only string content.
 */
public class HttpClient {
    protected ISocketFactory mFactory = null;

    protected Socket mSocket = null;
    protected InputStream mInputStream = null;
    protected OutputStream mOutputStream = null;

    protected InputStreamReader mInputStreamReader = null;
    protected OutputStreamWriter mOutputStreamWriter = null;
    protected BufferedReader mBufferedReader = null;
    protected SSLCertificateApprovalCallback mCertApprovalCallback = null;
    protected boolean mConnected = false;

    public HttpClient() {
    }

    public HttpClient(ISocketFactory factory) {
        mFactory = factory;
    }

    public HttpClient(ISocketFactory factory, SSLCertificateApprovalCallback certApprovalCallback) {
        mFactory = factory;
        mCertApprovalCallback = certApprovalCallback;
    }

    public void connect(String host, int port)
            throws IOException {
        if (mFactory != null) {
            if (mCertApprovalCallback == null) {
                mSocket = mFactory.makeSocket(host, port);
            } else {
                mSocket = mFactory.makeSocket(host, port, mCertApprovalCallback, null);
            }
        } else {
            mSocket = new Socket(host, port);
        }

        if (mSocket == null) {
            IOException e = new IOException("Couldn't make connection");

            throw e;
        }

        mInputStream = mSocket.getInputStream();
        mOutputStream = mSocket.getOutputStream();
        mInputStreamReader = new InputStreamReader(mInputStream, "UTF8");
        mBufferedReader = new BufferedReader(mInputStreamReader);
        mOutputStreamWriter = new OutputStreamWriter(mOutputStream, "UTF8");
        mConnected = true;
    }

    // Inserted by beomsuk
    public void connect(String host, int port, int timeout)
            throws IOException {
        if (mFactory != null) {
            mSocket = mFactory.makeSocket(host, port, timeout);
        } else {
            mSocket = new Socket(host, port);
        }

        if (mSocket == null) {
            IOException e = new IOException("Couldn't make connection");

            throw e;
        }

        mInputStream = mSocket.getInputStream();
        mOutputStream = mSocket.getOutputStream();
        mInputStreamReader = new InputStreamReader(mInputStream, "UTF8");
        mBufferedReader = new BufferedReader(mInputStreamReader);
        mOutputStreamWriter = new OutputStreamWriter(mOutputStream, "UTF8");
        mConnected = true;
    }

    // Insert end
    public boolean connected() {
        return mConnected;
    }

    /**
     * Sends a request to http server.
     * Returns a http response.
     */
    public HttpResponse send(HttpRequest request)
            throws IOException {
        HttpResponse resp = new HttpResponse();

        if (mOutputStream == null)
            throw new IOException("Output stream not initialized");
        request.write(mOutputStreamWriter);
        try {
            resp.parse(mBufferedReader);
        } catch (IOException e) {
            // XXX should we disconnect in all cases ?
            disconnect();
            throw e;
        }
        disconnect();
        return resp;
    }

    public void disconnect()
            throws IOException {
        mSocket.close();
        mInputStream = null;
        mOutputStream = null;
        mConnected = false;
    }

    public InputStream getInputStream() {
        return mInputStream;
    }

    public OutputStream getOutputStream() {
        return mOutputStream;
    }

    public BufferedReader getBufferedReader() {
        return mBufferedReader;
    }

    public InputStreamReader getInputStreamReader() {
        return mInputStreamReader;
    }

    public OutputStreamWriter getOutputStreamWriter() {
        return mOutputStreamWriter;
    }

    public Socket getSocket() {
        return mSocket;
    }

    /**
     * unit test
     */
    public static void main(String args[])
            throws Exception {
        HttpClient c = new HttpClient();
        HttpRequest req = new HttpRequest();
        HttpResponse resp = null;

        System.out.println("connecting to " + args[0] + " " + args[1]);
        c.connect(args[0], Integer.parseInt(args[1]));

        req.setMethod("GET");
        req.setURI(args[2]);
        if (args.length >= 4)
            req.setHeader("Connection", args[3]);
        resp = c.send(req);

        System.out.println("version " + resp.getHttpVers());
        System.out.println("status code " + resp.getStatusCode());
        System.out.println("reason " + resp.getReasonPhrase());
        System.out.println("content " + resp.getContent());

        //String lenstr = resp.getHeader("Content-Length");
        //System.out.println("content len is "+lenstr);
        //int length = Integer.parseInt(lenstr);
        //char[] content = new char[length];
        //c.mBufferedReader.read(content, 0, content.length);
        //System.out.println(content);

        if (args.length >= 4 && args[3].equalsIgnoreCase("keep-alive")) {
            for (int i = 0; i < 2; i++) {
                if (i == 1)
                    req.setHeader("Connection", "Close");
                resp = c.send(req);
                System.out.println("version " + resp.getHttpVers());
                System.out.println("status code " + resp.getStatusCode());
                System.out.println("reason " + resp.getReasonPhrase());
                System.out.println("content " + resp.getContent());
                //len = Integer.parseInt(resp.getHeader("Content-Length"));
                //System.out.println("content len is "+len);
                //msgbody = new char[len];
                //c.mBufferedReader.read(msgbody, 0, len);
                //System.out.println(content);
            }
        }
    }
}
