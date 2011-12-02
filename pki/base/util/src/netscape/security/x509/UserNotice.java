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

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;


/**
 * Represent the UserNotice Qualifier.
 *
 * UserNotice ::= SEQUENCE {
 *   noticeRef NoticeReference OPTIONAL,
 *   explicitText DisplayText OPTIONAL
 * }
 *
 * @author Thomas Kwan
 */
public class UserNotice extends Qualifier {

    /**
     *
     */
    private static final long serialVersionUID = 5770869942793748051L;
    private NoticeReference mNoticeReference = null;
    private DisplayText mDisplayText = null;

    public UserNotice(NoticeReference ref, DisplayText text) {
      mNoticeReference = ref;
      mDisplayText = text;
    }

    public UserNotice(DerValue val) throws IOException {
       if (val.tag != DerValue.tag_Sequence) {
           throw new IOException("Invalid encoding for UserNotice");
       }
       // case 0: no element
       if (val.data.available() == 0)
	 return;
       // case 1: 1 element
       DerValue inSeq = val.data.getDerValue();
       if (inSeq.tag == DerValue.tag_Sequence) {
         mNoticeReference = new NoticeReference(inSeq);
       } else { 
         mDisplayText = new DisplayText(inSeq);
       }
       if (val.data.available() == 0)
	 return;
       // case 2: 2 elements
       mDisplayText = new DisplayText(val.data.getDerValue());
    }

    public NoticeReference getNoticeReference() {
        return mNoticeReference;
    }

    public DisplayText getDisplayText() {
        return mDisplayText;
    }

    /**
     * Write the UserNotice to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the object to.
     * @exception IOException on errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

	// OPTIONAL
	if (mNoticeReference != null) {
        	mNoticeReference.encode(tmp);
	}
	// OPTIONAL
        if (mDisplayText != null) {
                mDisplayText.encode(tmp);
        }
        out.write(DerValue.tag_Sequence,tmp);
    }
}
