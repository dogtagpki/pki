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

import org.mozilla.jss.pkix.primitive.EncryptedPrivateKeyInfo;
import org.mozilla.jss.pkix.primitive.PrivateKeyInfo;

public class PKCS12KeyInfo {

    EncryptedPrivateKeyInfo encPrivateKeyInfo;
    PrivateKeyInfo privateKeyInfo;
    String subjectDN;

    public PKCS12KeyInfo() {
    }

    public EncryptedPrivateKeyInfo getEncPrivateKeyInfo() {
        return encPrivateKeyInfo;
    }

    public void setEncPrivateKeyInfo(EncryptedPrivateKeyInfo encPrivateKeyInfo) {
        this.encPrivateKeyInfo = encPrivateKeyInfo;
    }

    public PrivateKeyInfo getPrivateKeyInfo() {
        return privateKeyInfo;
    }

    public void setPrivateKeyInfo(PrivateKeyInfo privateKeyInfo) {
        this.privateKeyInfo = privateKeyInfo;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }
}
