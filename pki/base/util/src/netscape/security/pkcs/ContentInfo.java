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
package netscape.security.pkcs;

import java.io.IOException;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;

/**
 * A ContentInfo type, as defined in PKCS#7.
 * 
 * @version 1.12
 * @author Benjamin Renaud
 */

public class ContentInfo {

    // pkcs7 pre-defined content types
    private static int[] pkcs7 = { 1, 2, 840, 113549, 1, 7 };
    private static int[] data = { 1, 2, 840, 113549, 1, 7, 1 };
    private static int[] sdata = { 1, 2, 840, 113549, 1, 7, 2 };
    private static int[] edata = { 1, 2, 840, 113549, 1, 7, 3 };
    private static int[] sedata = { 1, 2, 840, 113549, 1, 7, 4 };
    private static int[] ddata = { 1, 2, 840, 113549, 1, 7, 5 };
    private static int[] crdata = { 1, 2, 840, 113549, 1, 7, 6 };

    public static final ObjectIdentifier PKCS7_OID = new ObjectIdentifier(pkcs7);

    public static final ObjectIdentifier DATA_OID = new ObjectIdentifier(data);

    public static final ObjectIdentifier SIGNED_DATA_OID = new ObjectIdentifier(
            sdata);

    public static final ObjectIdentifier ENVELOPED_DATA_OID = new ObjectIdentifier(
            edata);

    public static final ObjectIdentifier SIGNED_AND_ENVELOPED_DATA_OID = new ObjectIdentifier(
            sedata);

    public static final ObjectIdentifier DIGESTED_DATA_OID = new ObjectIdentifier(
            ddata);

    public static final ObjectIdentifier ENCRYPTED_DATA_OID = new ObjectIdentifier(
            crdata);

    ObjectIdentifier contentType;
    DerValue content; // OPTIONAL

    public ContentInfo(ObjectIdentifier contentType, DerValue content) {
        this.contentType = contentType;
        this.content = content;
    }

    /**
     * Make a contentInfo of type data.
     */
    public ContentInfo(byte[] bytes) {
        DerValue octetString = new DerValue(DerValue.tag_OctetString, bytes);
        this.contentType = DATA_OID;
        this.content = octetString;
    }

    public ContentInfo(DerInputStream derin) throws IOException,
            ParsingException {
        DerInputStream disType;
        DerInputStream disTaggedContent;
        DerValue type;
        DerValue taggedContent;
        DerValue[] typeAndContent;
        DerValue[] contents;

        typeAndContent = derin.getSequence(2);

        // Parse the content type
        type = typeAndContent[0];
        disType = new DerInputStream(type.toByteArray());
        contentType = disType.getOID();

        // Parse the content (OPTIONAL field).
        // Skip the [0] EXPLICIT tag by pretending that the content is the one
        // and only element in an implicitly tagged set
        if (typeAndContent.length > 1) { // content is OPTIONAL
            taggedContent = typeAndContent[1];
            disTaggedContent = new DerInputStream(taggedContent.toByteArray());
            contents = disTaggedContent.getSet(1, true);
            content = contents[0];
        }
    }

    public DerValue getContent() {
        return content;
    }

    public byte[] getData() throws IOException {
        if (contentType.equals(DATA_OID)) {
            return content.getOctetString();
        }
        throw new IOException("content type is not DATA: " + contentType);
    }

    public void encode(DerOutputStream out) throws IOException {
        DerOutputStream contentDerCode;
        DerOutputStream seq;
        DerValue taggedContent;

        contentDerCode = new DerOutputStream();
        content.encode(contentDerCode);
        // Add the [0] EXPLICIT tag in front of the content encoding
        taggedContent = new DerValue((byte) 0xA0, contentDerCode.toByteArray());

        seq = new DerOutputStream();
        seq.putOID(contentType);
        seq.putDerValue(taggedContent);

        out.write(DerValue.tag_Sequence, seq);
    }

    /**
     * Returns a byte array representation of the data held in the content
     * field.
     */
    public byte[] getContentBytes() throws IOException {
        DerInputStream dis = new DerInputStream(content.toByteArray());
        return dis.getOctetString();
    }

    public String toString() {
        String out = "";

        out += "Content Info Sequence\n\tContent type: " + contentType + "\n";
        out += "\tContent: " + content;
        return out;
    }
}
