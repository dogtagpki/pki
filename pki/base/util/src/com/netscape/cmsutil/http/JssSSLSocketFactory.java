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


import java.net.*;
import java.io.*;
import netscape.ldap.*;
import org.mozilla.jss.ssl.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.crypto.X509Certificate;

import com.netscape.cmsutil.net.*;

/**
 * Uses NSS ssl socket.
 *
 * @version $Revision$ $Date$
 */
public class JssSSLSocketFactory implements ISocketFactory {
    private String mClientAuthCertNickname = null;
    private	SSLSocket s = null;

    public JssSSLSocketFactory() {
    }

    public JssSSLSocketFactory(String certNickname) {
        mClientAuthCertNickname = certNickname;
    }

    // XXX remove these static SSL cipher suite initializations later on.
    static final int cipherSuites[] = {
            SSLSocket.SSL3_RSA_WITH_RC4_128_MD5,
            SSLSocket.SSL3_RSA_WITH_3DES_EDE_CBC_SHA,
            SSLSocket.SSL3_RSA_WITH_DES_CBC_SHA,
            SSLSocket.SSL3_RSA_EXPORT_WITH_RC4_40_MD5,
            SSLSocket.SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
            SSLSocket.SSL3_RSA_WITH_NULL_MD5,
            0
        };
	
    static {
        int i;

        for (i = SSLSocket.SSL2_RC4_128_WITH_MD5;
            i <= SSLSocket.SSL2_RC2_128_CBC_EXPORT40_WITH_MD5; ++i) {
            try {
                SSLSocket.setCipherPreferenceDefault(i, true);
            } catch( SocketException e) {
            }
        }
        //skip SSL_EN_IDEA_128_EDE3_CBC_WITH_MD5
        for (i = SSLSocket.SSL2_DES_64_CBC_WITH_MD5;
            i <= SSLSocket.SSL2_DES_192_EDE3_CBC_WITH_MD5; ++i) {
            try {
                SSLSocket.setCipherPreferenceDefault(i, true);
            } catch( SocketException e) {
            }
        }
        for (i = 0; cipherSuites[i] != 0; ++i) {
            try {
                SSLSocket.setCipherPreferenceDefault(cipherSuites[i], true);
            } catch( SocketException e) {
            }
        }
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
                X509Certificate cert = CryptoManager.getInstance().findCertByNickname(mClientAuthCertNickname);

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

    class ClientHandshakeCB implements SSLHandshakeCompletedListener {
        Object sc;

        public ClientHandshakeCB(Object sc) {
            this.sc = sc;
        }
	 
        public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
        }
    }
}

