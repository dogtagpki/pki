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

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

import org.mozilla.jss.CryptoManager;
//import org.mozilla.jss.ssl.SSLAlertDescription;
//import org.mozilla.jss.ssl.SSLAlertEvent;
//import org.mozilla.jss.ssl.SSLAlertLevel;
import org.mozilla.jss.ssl.SSLSocketListener;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLClientCertificateSelectionCallback;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLHandshakeCompletedListener;
import org.mozilla.jss.ssl.SSLSocket;

import com.netscape.cmsutil.net.ISocketFactory;
import com.netscape.cmsutil.crypto.CryptoUtil;
//import org.dogtagpki.server.PKIClientSocketListener;

/**
 * Uses NSS ssl socket.
 *
 * @version $Revision$ $Date$
 */
public class JssSSLSocketFactory implements ISocketFactory {
    private String mClientAuthCertNickname = null;
    private String mClientCiphers = null;
    private SSLSocket soc = null;
    private SSLSocketListener socListener = null;

    public JssSSLSocketFactory() {
    }

    public JssSSLSocketFactory(String certNickname) {
        mClientAuthCertNickname = certNickname;
    }

    public JssSSLSocketFactory(String certNickname, String ciphers) {
        if (certNickname != null)
            mClientAuthCertNickname = certNickname;

        if (ciphers != null)
            mClientCiphers = ciphers;
    }

    public Socket makeSocket(String host, int port)
            throws IOException, UnknownHostException {

        if (this.socListener != null) {
System.out.println("JssSSLSocketFactory.makeSocket:  this.socListener not null");
            return makeSocket(host, port, null, null, 0, socListener);
        } else {
System.out.println("JssSSLSocketFactory.makeSocket:  this.socListener null");
            return makeSocket(host, port, null, null, 0, null);
        }
    }

    public Socket makeSocket(String host, int port,
            SSLSocketListener socListener // for auditing purposes
        ) throws IOException, UnknownHostException {

            return makeSocket(host, port, null, null, 0, socListener);
    }

    public Socket makeSocket(String host, int port,
            SSLCertificateApprovalCallback certApprovalCallback,
            SSLClientCertificateSelectionCallback clientCertCallback,
            int timeout // milliseconds
        ) throws IOException, UnknownHostException {

        if (this.socListener != null)
            return makeSocket(host, port, null, null, 0, socListener);
        else
            return makeSocket(host, port, null, null, 0, null);
    }

    public Socket makeSocket(String host, int port,
            SSLCertificateApprovalCallback certApprovalCallback,
            SSLClientCertificateSelectionCallback clientCertCallback,
            int timeout, // milliseconds
            SSLSocketListener socListener // for auditing purposes
        ) throws IOException, UnknownHostException {

        String method = "JssSSLSocketFactory.makeSocket: ";
        try {
            /*
             * let inherit tls range and cipher settings
             * unless it's overwritten by config
             */
            if (mClientCiphers != null)
                CryptoUtil.setClientCiphers(mClientCiphers);
            soc = new SSLSocket(host, port, null, 0, certApprovalCallback,
                    clientCertCallback);
            soc.setUseClientMode(true);
            soc.setSoTimeout(timeout);

            SSLHandshakeCompletedListener listener = null;

            listener = new ClientHandshakeCB(this);
            soc.addHandshakeCompletedListener(listener);

            if (mClientAuthCertNickname != null) {
                // 052799 setClientCertNickname does not
                // report error if the nickName is invalid.
                // So we check this ourself using
                // findCertByNickname
                CryptoManager.getInstance().findCertByNickname(mClientAuthCertNickname);

                soc.setClientCertNickname(mClientAuthCertNickname);
            }
            boolean verbose = true;
//cfu
            if (socListener != null) {
                System.out.println("JssSSLSocketFactory.makeSocket: calling addSocketListener");
                addSocketListener(socListener);
            } else {
                System.out.println("JssSSLSocketFactory.makeSocket: NOT calling addSocketListener");
            }
            soc.forceHandshake();

        } catch (org.mozilla.jss.crypto.ObjectNotFoundException e) {
            throw new IOException(e.toString(), e);

        } catch (org.mozilla.jss.crypto.TokenException e) {
            throw new IOException(e.toString(), e);

        } catch (UnknownHostException e) {
            throw e;

        } catch (IOException e) {
            throw e;

        } catch (Exception e) {
            throw new IOException(e.toString(), e);
        }

        return soc;
    }

    public Socket makeSocket(String host, int port,
            int timeout // milliseconds
        ) throws IOException, UnknownHostException {

        if (this.socListener != null)
            return makeSocket(host, port, timeout, socListener);
        else
            return makeSocket(host, port, timeout, null);
    }

    public Socket makeSocket(String host, int port,
            int timeout, // milliseconds
            SSLSocketListener socListener // for auditing purposes
        ) throws IOException, UnknownHostException {

        if (socListener != null)
            this.socListener = socListener;
        Thread t = new ConnectAsync(this, host, port);

        t.start();
        try {
            t.join(timeout);
        } catch (InterruptedException e) {
        }

        if (t.isAlive()) {
        }

        return soc;
    }

    public void addSocketListener(SSLSocketListener socListener) {
        if (this.soc != null) {
            soc.addSocketListener(socListener);
        }
    }

    public void log(int level, String msg) {
    }

    static class ClientHandshakeCB implements SSLHandshakeCompletedListener {
        Object sc;

        public ClientHandshakeCB(Object sc) {
            this.sc = sc;
        }

        public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
        }
    }
}
