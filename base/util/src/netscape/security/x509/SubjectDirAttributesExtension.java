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
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;

/**
 * This class represents the Subject Directory Attributes Extension.
 *
 * <p>
 * The subject directory attributes extension is not recommended as an essential part of this profile, but it may be
 * used in local environments. This extension MUST be non-critical.
 *
 * <pre>
 * The ASN.1 syntax for this extension is:
 *
 *    SubjectDirectoryAttributes ::= SEQUENCE (1..MAX) OF Attribute
 *
 *    Attribute	::= SEQUENCE {
 * type		AttributeType,
 * 	value		SET OF AttributeValue
 *              	-- at least one value is required --}
 *
 *    AttributeType	::= OBJECT IDENTIFIER
 *
 *    AttributeValue	::= ANY
 *
 * </pre>
 *
 * @author Christine Ho
 * @version 1.7
 *
 * @see CertAttrSet
 * @see Extension
 */
public class SubjectDirAttributesExtension extends Extension
        implements CertAttrSet {

    /**
     *
     */
    private static final long serialVersionUID = -1215458115428197688L;

    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    //public static final String IDENT = "x509.info.extensions.SubjectDirectoryAttributes";
    public static final String IDENT = "Subject Directory Attributes";

    /**
     * Attribute names.
     */
    public static final String NAME = "SubjectDirectoryAttributes";

    // Private data members
    private Vector<Attribute> attrList = new Vector<Attribute>();

    // Encode this extension value
    private void encodeThis() throws IOException {
        try (DerOutputStream out = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            //encoding the attributes
            Enumeration<Attribute> attrs = attrList.elements();
            while (attrs.hasMoreElements()) {
                Attribute attr = attrs.nextElement();
                attr.encode(tmp);
            }

            out.write(DerValue.tag_SequenceOf, tmp);
            this.extensionValue = out.toByteArray();
        }
    }

    // Decode this extension value
    private void decodeThis(DerValue derVal) throws IOException {

        if (derVal.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for " +
                    "Subject Directory Attribute extension.");
        }

        if (derVal.data.available() == 0) {
            throw new IOException(NAME + " No data available in "
                                   + "passed DER encoded value.");
        }

        // Decode all the Attributes
        while (derVal.data.available() != 0) {
            DerValue encAttr = derVal.data.getDerValue();
            Attribute attr = new Attribute(encAttr);
            attrList.addElement(attr);
        }
    }

    /**
     * Default constructor for this object.
     *
     * @param derVal Der encoded value of this extension
     */
    public SubjectDirAttributesExtension(DerValue derVal) throws IOException {

        this.extensionId = PKIXExtensions.SubjectDirectoryAttributes_Id;
        this.critical = false;
        decodeThis(derVal);
    }

    /**
     * Default constructor for this object.
     *
     * @param list Attribute object list
     */
    public SubjectDirAttributesExtension(Attribute[] list) throws IOException {

        this.extensionId = PKIXExtensions.SubjectDirectoryAttributes_Id;
        this.critical = false;

        if ((list == null) || (list.length == 0)) {
            throw new IOException("No data available in "
                                   + "passed Attribute List.");
        }

        // add the Attributes
        for (int i = 0; i < list.length; i++) {
            attrList.addElement(list[i]);
        }
    }

    /**
     * Constructor from parsing extension
     *
     * @param list Attribute object list
     */
    public SubjectDirAttributesExtension(Boolean crit, Object value)
            throws IOException {

        this.extensionId = PKIXExtensions.SubjectDirectoryAttributes_Id;
        this.critical = crit.booleanValue();

        if (!(value instanceof byte[]))
            throw new IOException(NAME + "Illegal argument type");
        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        System.arraycopy(value, 0, extValue, 0, len);

        this.extensionValue = extValue;
        decodeThis(new DerValue(extValue));
    }

    /**
     * Constructor for this object.
     *
     * @param list Attribute object list
     * @param critical The criticality
     */
    public SubjectDirAttributesExtension(Attribute[] list, boolean critical)
            throws IOException {

        this.extensionId = PKIXExtensions.SubjectDirectoryAttributes_Id;
        this.critical = critical;

        if ((list == null) || (list.length == 0)) {
            throw new IOException("No data available in "
                                   + "passed Attribute List.");
        }

        // add the Attributes
        for (int i = 0; i < list.length; i++) {
            attrList.addElement(list[i]);
        }
    }

    /**
     * Return user readable form of extension.
     */
    public String toString() {

        String s = super.toString() + "SubjectDirectoryAttributes:[\n";

        Enumeration<Attribute> attrs = attrList.elements();
        StringBuffer tempBuffer = new StringBuffer();
        while (attrs.hasMoreElements()) {
            Attribute attr = attrs.nextElement();
            tempBuffer.append(attr.toString());
        }
        s += tempBuffer.toString();
        return (s + "]\n");
    }

    /**
     * Decode the extension from the InputStream.
     *
     * @param in the InputStream to unmarshal the contents from.
     * @exception IOException on decoding or validity errors.
     */
    public void decode(InputStream in) throws IOException {
        DerValue val = new DerValue(in);
        decodeThis(val);
    }

    /**
     * Encode this extension value to the output stream.
     *
     * @param out the DerOutputStream to encode the extension to.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        if (extensionValue == null) {
            this.extensionId = PKIXExtensions.SubjectDirectoryAttributes_Id;
            this.critical = false;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        throw new IOException("Attribute name not recognized by " +
                "CertAttrSet:SubjectDirectoryAttributes.");
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        throw new IOException("Attribute name not recognized by " +
                "CertAttrSet:SubjectDirectoryAttributes.");
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        throw new IOException("Attribute name not recognized by " +
                "CertAttrSet:SubjectDirectoryAttributes.");
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }

    /**
     * Returns an enumeration of attributes in the extension.
     */
    public Enumeration<Attribute> getAttributesList() {
        if (attrList == null)
            return null;
        return attrList.elements();
    }
}
