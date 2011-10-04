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
package com.netscape.certsrv.cert;


import com.netscape.certsrv.base.*;
import java.security.cert.*;


/**
 * Interface for handling cross certs
 *
 * @version $Revision$, $Date$
 */
public interface ICrossCertPairSubsystem extends ISubsystem {

    /**
     * "import" the CA cert cross-signed by another CA (potentially a
     * bridge CA) into internal ldap db.
     * If publishing is turned on, and 
     * if matches up a pair, then publish to publishing directory
     * otherwise, leave in internal ldap db and wait for it's matching 
     * pair
     * @param certBytes binary byte array of the cert
	 * @exception EBaseException when certBytes conversion to X509
	 * certificate fails
     */
    public void importCert(byte[] certBytes) throws EBaseException;

    /**
     * publish all cert pairs, if publisher is on
	 * @exception EBaseException when publishing fails
     */
    public void publishCertPairs() throws EBaseException;

	/**
	 * convert byte array to X509Certificate
	 * @return X509Certificate the X509Certificate class
	 * representation of the certificate byte array
	 * @exception CertificateException when conversion fails
	 */
    public X509Certificate byteArray2X509Cert(byte[] certBytes) throws CertificateException;
}
