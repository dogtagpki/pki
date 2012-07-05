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
import java.util.Vector;

import netscape.security.util.BigInt;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * Represent the NoticeReference.
 *
 * NoticeReference ::= SEQUENCE {
 * organization DisplayText,
 * noticeNumbers SEQUENCE OF INTEGER
 * }
 *
 * @author Thomas Kwan
 */
public class NoticeReference implements Serializable {

    private static final long serialVersionUID = 1986080941078808200L;
    private DisplayText mOrg = null;
    private int mNumbers[] = null;

    public NoticeReference(DisplayText org, int numbers[]) {
        mOrg = org;
        mNumbers = numbers;
    }

    public NoticeReference(DerValue val) throws IOException {
        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for NoticeReference");
        }
        mOrg = new DisplayText(val.data.getDerValue());
        DerValue integers = val.data.getDerValue();
        if (integers.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for NoticeReference (integers)");
        }
        Vector<BigInt> num = new Vector<BigInt>();
        while (integers.data.available() != 0) {
            DerValue i = integers.data.getDerValue();
            BigInt bigI = i.getInteger();
            num.addElement(bigI);
        }
        if (num.size() <= 0)
            return;
        mNumbers = new int[num.size()];
        for (int i = 0; i < num.size(); i++) {
            mNumbers[i] = num.elementAt(i).toInt();
        }
    }

    public DisplayText getOrganization() {
        return mOrg;
    }

    public int[] getNumbers() {
        return mNumbers;
    }

    /**
     * Write the NoticeReference to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the object to.
     * @exception IOException on errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        mOrg.encode(tmp);
        DerOutputStream iseq = new DerOutputStream();
        for (int i = 0; i < mNumbers.length; i++) {
            iseq.putInteger(new BigInt(mNumbers[i]));
        }
        tmp.write(DerValue.tag_Sequence, iseq);
        out.write(DerValue.tag_Sequence, tmp);
    }
}
