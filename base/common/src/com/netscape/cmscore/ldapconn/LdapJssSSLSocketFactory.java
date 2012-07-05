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
package com.netscape.cmscore.ldapconn;

import java.io.IOException;
import java.net.Socket;
import java.net.UnknownHostException;

import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSSLSocketFactoryExt;

import org.mozilla.jss.ssl.SSLHandshakeCompletedEvent;
import org.mozilla.jss.ssl.SSLHandshakeCompletedListener;
import org.mozilla.jss.ssl.SSLSocket;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.logging.ILogger;

/**
 * Uses HCL ssl socket.
 *
 * @author Lily Hsiao lhsiao@netscape.com
 */
public class LdapJssSSLSocketFactory implements LDAPSSLSocketFactoryExt {
    private String mClientAuthCertNickname = null;
    private boolean mClientAuth = false;

    public LdapJssSSLSocketFactory() {
    }

    public LdapJssSSLSocketFactory(String certNickname) {
        mClientAuthCertNickname = certNickname;
    }

    public Socket makeSocket(String host, int port) throws LDAPException {
        SSLSocket s = null;

        try {
            SSLSocket.enableSSL2Default(false);
            s = new SSLSocket(host, port);
            s.setUseClientMode(true);
            s.enableSSL2(false);
            //TODO Do we really want to set the default each time?
            SSLSocket.enableSSL2Default(false);
            s.enableV2CompatibleHello(false);

            SSLHandshakeCompletedListener listener = null;

            listener = new ClientHandshakeCB(this);
            s.addHandshakeCompletedListener(listener);

            if (mClientAuthCertNickname != null) {
                mClientAuth = true;
                CMS.debug(
                        "LdapJssSSLSocket set client auth cert nickname" +
                                mClientAuthCertNickname);
                s.setClientCertNickname(mClientAuthCertNickname);
            }
            s.forceHandshake();
        } catch (UnknownHostException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_LDAPCONN_UNKNOWN_HOST"));
            throw new LDAPException(
                    "Cannot Create JSS SSL Socket - Unknown host");
        } catch (IOException e) {
            if (s != null) {
                try {
                    s.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_LDAPCONN_IO_ERROR", e.toString()));
            throw new LDAPException("IO Error creating JSS SSL Socket");
        }
        return s;
    }

    public boolean isClientAuth() {
        return mClientAuth;
    }

    public Object getCipherSuites() {
        return null;
    }

    public void log(int level, String msg) {
    }

    static class ClientHandshakeCB implements SSLHandshakeCompletedListener {
        Object sc;

        public ClientHandshakeCB(Object sc) {
            this.sc = sc;
        }

        public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
            CMS.debug("SSL handshake happened");
        }
    }
}
