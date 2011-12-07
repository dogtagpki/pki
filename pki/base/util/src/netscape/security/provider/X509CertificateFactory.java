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
package netscape.security.provider;

import java.io.InputStream;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactorySpi;
import java.util.Collection;

import netscape.security.x509.X509CRLImpl;
import netscape.security.x509.X509CertImpl;
import netscape.security.x509.X509ExtensionException;

public class X509CertificateFactory extends CertificateFactorySpi {

    public Certificate engineGenerateCertificate(InputStream inStream)
            throws CertificateException {
        return new X509CertImpl(inStream);
    }

    public Collection engineGenerateCertificates(InputStream inStream)
            throws CertificateException {
        return null;
    }

    public CRL engineGenerateCRL(InputStream inStream) throws CRLException {
        X509CRLImpl crl = null;
        try {
            crl = new X509CRLImpl(inStream);
        } catch (X509ExtensionException e) {
            ;
        }

        return crl;
    }

    public Collection engineGenerateCRLs(InputStream inStream)
            throws CRLException {
        return null;
    }

}
