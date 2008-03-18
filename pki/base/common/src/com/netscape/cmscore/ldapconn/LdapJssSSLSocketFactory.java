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


import java.net.*;
import java.io.*;
import netscape.ldap.*;
import org.mozilla.jss.ssl.*;
import com.netscape.certsrv.logging.*;
import com.netscape.certsrv.apps.*;
import com.netscape.certsrv.ldap.*;


/**
 * Uses HCL ssl socket.
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
            s = new SSLSocket(host, port);
            s.setUseClientMode(true);

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

    class ClientHandshakeCB implements SSLHandshakeCompletedListener {
        Object sc;

        public ClientHandshakeCB(Object sc) {
            this.sc = sc;
        }
	 
        public void handshakeCompleted(SSLHandshakeCompletedEvent event) {
            CMS.debug("SSL handshake happened");
        }
    }
}

