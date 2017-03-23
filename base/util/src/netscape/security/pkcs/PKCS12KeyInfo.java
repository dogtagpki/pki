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

import org.mozilla.jss.crypto.PrivateKey;

public class PKCS12KeyInfo {

    private PrivateKey privateKey;
    private byte[] epkiBytes;
    BigInteger id;
    String subjectDN;

    public PKCS12KeyInfo() {
    }

    public PKCS12KeyInfo(PrivateKey k) {
        this.privateKey = k;
    }

    public PKCS12KeyInfo(byte[] epkiBytes) {
        this.epkiBytes = epkiBytes;
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public byte[] getEncryptedPrivateKeyInfoBytes() {
        return epkiBytes;
    }

    public BigInteger getID() {
        return id;
    }

    public void setID(BigInteger id) {
        this.id = id;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }
}
