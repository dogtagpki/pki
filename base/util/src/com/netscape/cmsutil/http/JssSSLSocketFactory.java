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
import java.net.SocketException;
import java.net.UnknownHostException;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.ssl.SSLCertificateApprovalCallback;
import org.mozilla.jss.ssl.SSLClientCertificateSelectionCallback;
import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLHandshakeCompletedListener;
import org.mozilla.jss.ssl.SSLSocket;

import com.netscape.cmsutil.net.ISocketFactory;

/**
 * Uses NSS ssl socket.
 *
 * @version $Revision$ $Date$
 */
public class JssSSLSocketFactory implements ISocketFactory {
    private String mClientAuthCertNickname = null;
    private SSLSocket s = null;

    public JssSSLSocketFactory() {
    }

    public JssSSLSocketFactory(String certNickname) {
        mClientAuthCertNickname = certNickname;
    }

    public Socket makeSocket(String host, int port)
            throws IOException, UnknownHostException {
        return makeSocket(host, port, null, null);
    }

    public Socket makeSocket(String host, int port,
            SSLCertificateApprovalCallback certApprovalCallback,
            SSLClientCertificateSelectionCallback clientCertCallback)
            throws IOException, UnknownHostException {

        try {
            /*
             * let inherit tls range and cipher settings
             */
            s = new SSLSocket(host, port, null, 0, certApprovalCallback,
                    clientCertCallback);
            s.setUseClientMode(true);

            SSLHandshakeCompletedListener listener = null;

            listener = new ClientHandshakeCB(this);
            s.addHandshakeCompletedListener(listener);

            if (mClientAuthCertNickname != null) {
                // 052799 setClientCertNickname does not
                // report error if the nickName is invalid.
                // So we check this ourself using
                // findCertByNickname
                CryptoManager.getInstance().findCertByNickname(mClientAuthCertNickname);

                s.setClientCertNickname(mClientAuthCertNickname);
            }
            s.forceHandshake();
        } catch (org.mozilla.jss.crypto.ObjectNotFoundException e) {
            throw new IOException(e.toString());
        } catch (org.mozilla.jss.crypto.TokenException e) {
            throw new IOException(e.toString());
        } catch (UnknownHostException e) {
            throw e;
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException(e.toString());
        }
        return s;
    }

    public Socket makeSocket(String host, int port, int timeout)
            throws IOException, UnknownHostException {
        Thread t = new ConnectAsync(this, host, port);

        t.start();
        try {
            t.join(1000 * timeout);
        } catch (InterruptedException e) {
        }

        if (t.isAlive()) {
        }

        return s;
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
