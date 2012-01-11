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
 * This class implements the ASN.1 GeneralName object class.
 * <p>
 * The ASN.1 syntax for this is:
 * 
 * <pre>
 * GeneralName ::= CHOICE {
 *    otherName                       [0]     OtherName,
 *    rfc822Name                      [1]     IA5String,
 *    dNSName                         [2]     IA5String,
 *    x400Address                     [3]     ORAddress,
 *    directoryName                   [4]     Name,
 *    ediPartyName                    [5]     EDIPartyName,
 *    uniformResourceIdentifier       [6]     IA5String,
 *    iPAddress                       [7]     OCTET STRING,
 *    registeredID                    [8]     OBJECT IDENTIFIER
 * }
 * </pre>
 * 
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.7
 */
public class GeneralName implements GeneralNameInterface {

    /**
     *
     */
    private static final long serialVersionUID = 2244101501095555042L;
    // Private data members
    private GeneralNameInterface name = null;

    /**
     * Default constructor for the class.
     * 
     * @param name the selected CHOICE from the list.
     */
    public GeneralName(GeneralNameInterface name) {
        this.name = name;
    }

    /**
     * Create the object from its DER encoded value.
     * 
     * @param encName the DER encoded GeneralName.
     */
    public GeneralName(DerValue encName) throws IOException {
        short tag = (byte) (encName.tag & 0x1f);

        // NB. this is always encoded with the IMPLICIT tag 
        // The checks only make sense if we assume implicit tagging, 
        // with explicit tagging the form is always constructed. 
        switch (tag) {
        case GeneralNameInterface.NAME_RFC822:
            if (encName.isContextSpecific() && !encName.isConstructed()) {
                encName.resetTag(DerValue.tag_IA5String);
                name = new RFC822Name(encName);
            } else
                throw new IOException("Invalid encoding of RFC822 name");
            break;

        case GeneralNameInterface.NAME_DNS:
            if (encName.isContextSpecific() && !encName.isConstructed()) {
                encName.resetTag(DerValue.tag_IA5String);
                name = new DNSName(encName);
            } else
                throw new IOException("Invalid encoding of DNS name");
            break;

        case GeneralNameInterface.NAME_URI:
            if (encName.isContextSpecific() && !encName.isConstructed()) {
                encName.resetTag(DerValue.tag_IA5String);
                name = new URIName(encName);
            } else
                throw new IOException("Invalid encoding of URI");
            break;

        case GeneralNameInterface.NAME_IP:
            if (encName.isContextSpecific() && !encName.isConstructed()) {
                encName.resetTag(DerValue.tag_OctetString);
                name = new IPAddressName(encName);
            } else
                throw new IOException("Invalid encoding of IP address");
            break;

        case GeneralNameInterface.NAME_ANY:
            if (encName.isContextSpecific() && encName.isConstructed()) {
                encName.resetTag(DerValue.tag_OctetString);
                name = new OtherName(encName);
            } else
                throw new IOException("Invalid encoding of other name");
            break;

        case GeneralNameInterface.NAME_OID:
            if (encName.isContextSpecific() && !encName.isConstructed()) {
                encName.resetTag(DerValue.tag_ObjectId);
                name = new OIDName(encName);
            } else
                throw new IOException("Invalid encoding of OID name");
            break;

        case GeneralNameInterface.NAME_DIRECTORY:
            if (encName.isContextSpecific() && encName.isConstructed()) {
                // Unlike the other cases, DirectoryName is EXPLICITly
                // tagged, because the X.500 Name type is a CHOICE.
                // Therefore, the sequence is actually nested in the
                // content of this value.  We'll pretend it's an octet
                // string so we can get at the content bytes.
                encName.resetTag(DerValue.tag_OctetString);
                byte[] content = encName.getOctetString();
                name = new X500Name(content);
            } else
                throw new IOException("Invalid encoding of Directory name");
            break;

        case GeneralNameInterface.NAME_EDI:
            if (encName.isContextSpecific() && encName.isConstructed()) {
                encName.resetTag(DerValue.tag_Sequence);
                name = new EDIPartyName(encName);
            } else
                throw new IOException("Invalid encoding of EDI name");
            break;

        default:
            throw new IOException("Unrecognized GeneralName tag, ("
                                  + tag + ")");
        }
    }

    /**
     * Return the type of the general name.
     */
    public int getType() {
        return (name.getType());
    }

    /**
     * Return the name as user readable string
     */
    public String toString() {
        return (name.toString());
    }

    /**
     * Encode the name to the specified DerOutputStream.
     * 
     * @param out the DerOutputStream to encode the the GeneralName to.
     * @exception IOException on encoding errors.
     */
    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        name.encode(tmp);
        int nameType = name.getType();
        boolean constructedForm;

        if (nameType == GeneralNameInterface.NAME_ANY ||
                nameType == GeneralNameInterface.NAME_X400 ||
                nameType == GeneralNameInterface.NAME_DIRECTORY ||
                nameType == GeneralNameInterface.NAME_EDI) {
            constructedForm = true;
        } else {
            constructedForm = false;
        }

        if (nameType == GeneralNameInterface.NAME_DIRECTORY) {
            // EXPLICIT tag, because Name is a CHOICE type
            out.write(DerValue.createTag(DerValue.TAG_CONTEXT,
                             constructedForm, (byte) nameType), tmp);
        } else {
            // IMPLICIT tag, the default
            out.writeImplicit(DerValue.createTag(DerValue.TAG_CONTEXT,
                             constructedForm, (byte) nameType), tmp);
        }
    }
}
