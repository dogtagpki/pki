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
import java.io.Serializable;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * Represent the DisplayText.
 *
 * DisplayText ::= CHOICE {
 * visibleString VisibleString (SIZE (1..200)),
 * bmpString BMPString (SIZE (1..200)),
 * utf8String UTF8String (SIZE (1..200)),
 * }
 *
 * @author Thomas Kwan
 */
public class DisplayText implements Serializable {

    private static final long serialVersionUID = -6521458152495173328L;

    /** Tag value indicating an ASN.1 "BMPString" value. */
    public final static byte tag_IA5String = 0x16;
    public final static byte tag_BMPString = 0x1E;
    public final static byte tag_VisibleString = 0x1A;
    public final static byte tag_UTF8String = 0x0C;

    private byte mTag;
    private String mS = null;

    public DisplayText(byte tag, String s) {
        mTag = tag;
        mS = s;
    }

    public DisplayText(DerValue val) throws IOException {
        mTag = val.tag;
        mS = val.getAsString();
    }

    /**
     * Write the DisplayText to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the object to.
     * @exception IOException on errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        out.putStringType(mTag, mS);
    }

    public String getText() {
        return mS;
    }

    public String toString() {
        if (mTag == tag_IA5String) {
            return "IA5String: " + mS;
        } else if (mTag == tag_BMPString) {
            return "BMPString: " + mS;
        } else if (mTag == tag_VisibleString) {
            return "VisibleString: " + mS;
        } else {
            return "UTF8String: " + mS;
        }
    }
}
