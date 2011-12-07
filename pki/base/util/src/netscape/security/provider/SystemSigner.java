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

import java.security.Certificate;
import java.security.IdentityScope;
import java.security.InvalidParameterException;
import java.security.KeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Signer;

/**
 * SunSecurity signer.
 * 
 * @version 1.24, 09/12/97
 * @author Benjamin Renaud
 */
public class SystemSigner extends Signer {

    /** use serialVersionUID from JDK 1.1. for interoperability */
    private static final long serialVersionUID = -2127743304301557711L;

    /* This exists only for serialization bc and don't use it! */
    private boolean trusted = false;

    /**
     * Construct a signer with a given name.
     */
    public SystemSigner(String name) {
        super(name);
    }

    /**
     * Construct a signer with a name and a scope.
     * 
     * @param name the signer's name.
     * 
     * @param scope the scope for this signer.
     */
    public SystemSigner(String name, IdentityScope scope)
            throws KeyManagementException {

        super(name, scope);
    }

    /* friendly callback for set keys */
    void setSignerKeyPair(KeyPair pair) throws InvalidParameterException,
            KeyException {
        setKeyPair(pair);
    }

    /* friendly callback for getting private keys */
    PrivateKey getSignerPrivateKey() {
        return getPrivateKey();
    }

    void setSignerInfo(String s) {
        setInfo(s);
    }

    /**
     * Call back method into a protected method for package friends.
     */
    void addSignerCertificate(Certificate cert) throws KeyManagementException {
        addCertificate(cert);
    }

    void clearCertificates() throws KeyManagementException {
        Certificate[] certs = certificates();
        for (int i = 0; i < certs.length; i++) {
            removeCertificate(certs[i]);
        }
    }
}
