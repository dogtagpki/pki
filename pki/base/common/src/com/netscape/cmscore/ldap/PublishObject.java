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
package com.netscape.cmscore.ldap;

import netscape.security.x509.X509CRLImpl;
import netscape.security.x509.X509CertImpl;

/**
 * The object to publish or unpublish: a certificate or a CRL
 */
public class PublishObject {
    public static final String CERT = "cert";
    public static final String CERTS = "certs";
    public static final String CRL = "crl";
    private String mObjectType = null;
    private X509CertImpl mCert = null;
    private X509CertImpl[] mCerts = null;
    private X509CRLImpl mCRL = null;
    private int mIndex = 0;

    public PublishObject() {
    }

    public String getType() {
        return mObjectType;
    }

    public void setCert(X509CertImpl cert) {
        mObjectType = CERT;
        mCert = cert;
        mCerts = null;
        mCRL = null;
    }

    public X509CertImpl getCert() {
        return mCert;
    }

    public void setCerts(X509CertImpl[] certs) {
        mObjectType = CERTS;
        mCerts = certs;
        mCert = null;
        mCRL = null;
    }

    public X509CertImpl[] getCerts() {
        return mCerts;
    }

    public void setIndex(int index) {
        mIndex = index;
    }

    public int getIndex() {
        return mIndex;
    }

    public void setCRL(X509CRLImpl crl) {
        mObjectType = CRL;
        mCert = null;
        mCerts = null;
        mCRL = crl;
    }

    public X509CRLImpl getCRL() {
        return mCRL;
    }

}
