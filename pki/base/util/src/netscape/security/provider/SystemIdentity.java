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

import java.io.Serializable;
import java.security.Certificate;
import java.security.Identity;
import java.security.IdentityScope;
import java.security.InvalidParameterException;
import java.security.KeyManagementException;
import java.security.PublicKey;

/**
 * An identity.
 * 
 * @version 1.19, 09/12/97
 * @author Benjamin Renaud
 */

public class SystemIdentity extends Identity implements Serializable {

    /** use serialVersionUID from JDK 1.1. for interoperability */
    private static final long serialVersionUID = 9060648952088498478L;

    /* Free form additional information about this identity. */
    private String info;

    /* This exists only for serialization bc and don't use it! */
    private boolean trusted = false;

    public SystemIdentity(String name, IdentityScope scope)
            throws InvalidParameterException, KeyManagementException {
        super(name, scope);
    }

    void setIdentityInfo(String info) {
        super.setInfo(info);
    }

    String getIndentityInfo() {
        return super.getInfo();
    }

    /**
     * Call back method into a protected method for package friends.
     */
    void setIdentityPublicKey(PublicKey key) throws KeyManagementException {
        setPublicKey(key);
    }

    /**
     * Call back method into a protected method for package friends.
     */
    void addIdentityCertificate(Certificate cert) throws KeyManagementException {
        addCertificate(cert);
    }

    void clearCertificates() throws KeyManagementException {
        Certificate[] certs = certificates();
        for (int i = 0; i < certs.length; i++) {
            removeCertificate(certs[i]);
        }
    }
}
