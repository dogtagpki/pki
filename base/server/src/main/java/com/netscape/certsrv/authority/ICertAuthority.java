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
package com.netscape.certsrv.authority;

import org.mozilla.jss.netscape.security.x509.CertificateChain;
import org.mozilla.jss.netscape.security.x509.X500Name;
import org.mozilla.jss.netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.request.IRequestListener;

/**
 * Authority that handles certificates needed by the cert registration
 * servlets.
 * <P>
 *
 * @version $Revision$ $Date$
 */
public interface ICertAuthority extends IAuthority {

    /**
     * Returns CA's certificate chain.
     * <P>
     *
     * @return the Certificate Chain for the CA.
     */
    public CertificateChain getCACertChain();

    /**
     * Returns CA's certificate implementaion.
     * <P>
     *
     * @return CA's certificate.
     */
    public X509CertImpl getCACert() throws EBaseException;

    /**
     * Returns signing algorithms supported by the CA.
     * Dependent on CA's key type and algorithms supported by security lib.
     */
    public String[] getCASigningAlgorithms();

    /**
     * Returns authority's X500 Name. - XXX what's this for ??
     */
    public X500Name getX500Name();

    /**
     * Register a request listener
     */
    @Override
    public void registerRequestListener(IRequestListener l);

    /**
     * Remove a request listener
     */
    public void removeRequestListener(IRequestListener l);

    /**
     * Register a pending listener
     */
    @Override
    public void registerPendingListener(IRequestListener l);
}
