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

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class defines the EDIPartyName of the GeneralName choice.
 * The ASN.1 syntax for this is:
 * 
 * <pre>
 * EDIPartyName ::= SEQUENCE {
 *     nameAssigner  [0]  DirectoryString OPTIONAL,
 *     partyName     [1]  DirectoryString }
 * </pre>
 * 
 * @author Hemma Prafullchandra
 * @version 1.2
 * @see GeneralName
 * @see GeneralNames
 * @see GeneralNameInterface
 */
public class EDIPartyName implements GeneralNameInterface {

    /**
     *
     */
    private static final long serialVersionUID = -8669257424766789063L;
    // Private data members
    private static final byte TAG_ASSIGNER = 0;
    private static final byte TAG_PARTYNAME = 1;

    private String assigner = null;
    private String party = null;

    /**
     * Create the EDIPartyName object from the specified names.
     * 
     * @param assignerName the name of the assigner
     * @param partyName the name of the EDI party.
     */
    public EDIPartyName(String assignerName, String partyName) {
        this.assigner = assignerName;
        this.party = partyName;
    }

    /**
     * Create the EDIPartyName object from the specified name.
     * 
     * @param partyName the name of the EDI party.
     */
    public EDIPartyName(String partyName) {
        this.party = partyName;
    }

    /**
     * Create the EDIPartyName object from the passed encoded Der value.
     * 
     * @param derValue the encoded DER EDIPartyName.
     * @exception IOException on error.
     */
    public EDIPartyName(DerValue derValue) throws IOException {
        DerInputStream in = new DerInputStream(derValue.toByteArray());
        DerValue[] seq = in.getSequence(2);

        int len = seq.length;
        if (len < 1 || len > 2)
            throw new IOException("Invalid encoding of EDIPartyName");

        for (int i = 0; i < len; i++) {
            DerValue opt = seq[i];
            if (opt.isContextSpecific((byte) TAG_ASSIGNER) &&
                    !opt.isConstructed()) {
                if (assigner != null)
                    throw new IOException("Duplicate nameAssigner found in"
                                          + " EDIPartyName");
                opt = opt.data.getDerValue();
                assigner = opt.getAsString();
            }
            if (opt.isContextSpecific((byte) TAG_PARTYNAME) &&
                    !opt.isConstructed()) {
                if (party != null)
                    throw new IOException("Duplicate partyName found in"
                                          + " EDIPartyName");
                opt = opt.data.getDerValue();
                party = opt.getAsString();
            }
        }
    }

    /**
     * Return the type of the GeneralName.
     */
    public int getType() {
        return (GeneralNameInterface.NAME_EDI);
    }

    /**
     * Encode the EDI party name into the DerOutputStream.
     * 
     * @param out the DER stream to encode the EDIPartyName to.
     * @exception IOException on encoding errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tagged = new DerOutputStream();
        DerOutputStream tmp = new DerOutputStream();

        if (assigner != null) {
            DerOutputStream tmp2 = new DerOutputStream();
            // XXX - shd check is chars fit into PrintableString
            tmp2.putPrintableString(assigner);
            tagged.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                                 false, TAG_ASSIGNER), tmp2);
        }
        if (party == null)
            throw new IOException("Cannot have null partyName");

        // XXX - shd check is chars fit into PrintableString
        tmp.putPrintableString(party);
        tagged.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                                 false, TAG_PARTYNAME), tmp);

        out.write(DerValue.tag_Sequence, tagged);
    }

    /**
     * Return the printable string.
     */
    public String toString() {
        return ("EDIPartyName: " +
                 ((assigner == null) ? "" :
                         ("  nameAssigner = " + assigner + ","))
                 + "  partyName = " + party);
    }
}
