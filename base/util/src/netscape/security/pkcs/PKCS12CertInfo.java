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
// (C) 2016 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package netscape.security.pkcs;

import java.math.BigInteger;

import netscape.security.x509.X509CertImpl;

public class PKCS12CertInfo {

    BigInteger id;
    X509CertImpl cert;
    String nickname;
    String trustFlags;

    public PKCS12CertInfo() {
    }

    public BigInteger getID() {
        return id;
    }

    public void setID(BigInteger id) {
        this.id = id;
    }

    public X509CertImpl getCert() {
        return cert;
    }

    public void setCert(X509CertImpl cert) {
        this.cert = cert;
    }

    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
    }

    public String getTrustFlags() {
        return trustFlags;
    }

    public void setTrustFlags(String trustFlags) {
        this.trustFlags = trustFlags;
    }
}
