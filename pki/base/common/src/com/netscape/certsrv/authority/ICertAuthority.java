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

import netscape.security.x509.CertificateChain;
import netscape.security.x509.X500Name;
import netscape.security.x509.X509CertImpl;

import com.netscape.certsrv.dbs.certdb.ICertificateRepository;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.publish.IPublisherProcessor;
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
     * Retrieves the certificate repository for this authority.
     * <P>
     * 
     * @return the certificate repository.
     */
    public ICertificateRepository getCertificateRepository();

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
    public X509CertImpl getCACert();

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
    public void registerRequestListener(IRequestListener l);

    /**
     * Remove a request listener
     */
    public void removeRequestListener(IRequestListener l);

    /**
     * Register a pending listener
     */
    public void registerPendingListener(IRequestListener l);

    /**
     * get authority's publishing module if any.
     */
    public IPublisherProcessor getPublisherProcessor();

    /**
     * Returns the logging interface for this authority.
     * Using this interface both System and Audit events can be
     * logged.
     * 
     */
    public ILogger getLogger();

}
