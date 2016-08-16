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
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.Vector;

import netscape.ldap.LDAPException;
import netscape.ldap.LDAPSSLSocketFactoryExt;

import org.mozilla.jss.ssl.SSLClientCertificateSelectionCallback;
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
            /*
             * let inherit TLS range and cipher settings
             */

            if (mClientAuthCertNickname == null) {
                s = new SSLSocket(host, port);
            }
            else {
                //Let's create a selection callback in the case the client auth
                //No longer manually set the cert name.
                //This two step process, used in the JSS client auth test suite,
                //appears to be needed to get this working.

                Socket js = new Socket(InetAddress.getByName(host), port);
                s = new SSLSocket(js, host,
                        null,
                        new SSLClientCertificateSelectionCB(mClientAuthCertNickname));
            }

            s.setUseClientMode(true);
            s.enableV2CompatibleHello(false);

            SSLHandshakeCompletedListener listener = null;

            listener = new ClientHandshakeCB(this);
            s.addHandshakeCompletedListener(listener);

            if (mClientAuthCertNickname != null) {
                mClientAuth = true;
                CMS.debug("LdapJssSSLSocket: set client auth cert nickname " +
                        mClientAuthCertNickname);

                //We have already established the manual cert selection callback
                //Doing it this way will provide some debugging info on the candidate certs
            }
            s.forceHandshake();

        } catch (UnknownHostException e) {
            log(ILogger.LL_FAILURE,
                    CMS.getLogMessage("CMSCORE_LDAPCONN_UNKNOWN_HOST"));
            throw new LDAPException(
                    "Cannot Create JSS SSL Socket - Unknown host: " + e);

        } catch (IOException e) {
            if (s != null) {
                try {
                    s.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
            log(ILogger.LL_FAILURE, CMS.getLogMessage("CMSCORE_LDAPCONN_IO_ERROR", e.toString()));
            throw new LDAPException("IO Error creating JSS SSL Socket: " + e);
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

    static class SSLClientCertificateSelectionCB implements SSLClientCertificateSelectionCallback {
        String desiredCertName = null;

        public SSLClientCertificateSelectionCB(String clientAuthCertNickname) {
            CMS.debug("SSLClientCertificateSelectionCB: Setting desired cert nickname to: " + clientAuthCertNickname);
            desiredCertName = clientAuthCertNickname;
        }

        @Override
        public String select(Vector certs) {

            CMS.debug("SSLClientCertificatSelectionCB: Entering!");

            if(desiredCertName == null) {
                return null;
            }

            @SuppressWarnings("unchecked")
            Iterator<String> itr = certs.iterator();
            String selection = null;

            while(itr.hasNext()){
                String candidate = itr.next();
                CMS.debug("Candidate cert: " + candidate);
                if(desiredCertName.equalsIgnoreCase(candidate)) {
                    selection = candidate;
                    CMS.debug("SSLClientCertificateSelectionCB: desired cert found in list: " + desiredCertName);
                    break;
                }
            }

            CMS.debug("SSLClientCertificateSelectionCB: returning: " + selection);
            return selection;

        }

    }

}
