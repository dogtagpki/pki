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
package netscape.security.x509;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.cert.X509Certificate;

import netscape.security.pkcs.ContentInfo;
import netscape.security.pkcs.PKCS7;
import netscape.security.pkcs.SignerInfo;

public class CertificateChain implements Serializable {
    public CertificateChain() {
    }

    /**
     * constructs a certificate chain from a certificate.
     * 
     * @param cert a certificate
     */
    public CertificateChain(X509Certificate cert) {
        mChain = new X509Certificate[1];
        mChain[0] = cert;
    }

    /**
     * constructs a certificate chain from a X509 certificate array.
     * 
     * @param chain a certificate array.
     */
    public CertificateChain(X509Certificate[] chain) {
        mChain = (X509Certificate[]) chain.clone();
    }

    /**
     * returns the certificate at specified index in chain.
     * 
     * @param index the index.
     * @return the X509 certificate at the given index.
     */
    public X509Certificate getCertificate(int index) {
        return mChain[index];
    }

    /**
     * returns the first certificate in chain.
     * 
     * @return the X509 certificate at the given index.
     */
    public X509Certificate getFirstCertificate() {
        return mChain[0];
    }

    /**
     * returns the certificate chain as an array of X509 certificates.
     * 
     * @return an array of X509 Certificates.
     */
    public X509Certificate[] getChain() {
        return (X509Certificate[]) mChain.clone();
    }

    public void encode(OutputStream out) throws IOException {
        encode(out, true);
    }

    /**
     * encode in PKCS7 blob.
     */
    public void encode(OutputStream out, boolean sort) throws IOException {
        PKCS7 p7 = new PKCS7(new AlgorithmId[0], new ContentInfo(new byte[0]),
                mChain, new SignerInfo[0]);
        p7.encodeSignedData(out, sort);
    }

    /**
     * decode from PKCS7 blob.
     */
    public void decode(InputStream in) throws IOException {
        PKCS7 p7 = new PKCS7(in);
        mChain = p7.getCertificates();
    }

    /**
     * for serialization
     */
    private void writeObject(java.io.ObjectOutputStream out) throws IOException {
        encode(out);
    }

    /**
     * for serialization
     */
    private void readObject(java.io.ObjectInputStream in) throws IOException {
        decode(in);
    }

    /**
     * Converts the certificate chain to a readable string.
     */
    public String toString() {
        String s = "[\n";
        if (mChain == null)
            return "[empty]";
        for (int i = 0; i < mChain.length; i++) {
            s += mChain[i].toString();
        }
        s += "]\n";
        return s;
    }

    private X509Certificate[] mChain = null;
}
