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
import java.io.OutputStream;
import java.io.Serializable;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerEncoder;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;

/**
 * An attribute, as identified by some attribute ID, has some particular values.
 * Values are as a rule ASN.1 printable strings. A conventional set of type IDs
 * is recognized when parsing. The following shows the syntax:
 *
 * <pre>
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
 * Refer to draft-ietf-pkix-ipki-part1-11 for the support attributes listed on
 * page 96 of the internet draft. The are listed here for easy reference: name,
 * common name, surname, given name, initials, generation qualifier, dn qualifier,
 * country name, locality name, state or province name, organization name, organization
 * unit name, title, pkcs9 email. Not all the attributes are supported. Please check
 * the X500NameAttrMap for defined attributes.
 *
 * @author Christine Ho
 */

public final class Attribute implements Serializable, DerEncoder {

    /**
     *
     */
    private static final long serialVersionUID = -931486084625476764L;
    //private variables
    ObjectIdentifier oid;
    Vector<String> valueSet = new Vector<String>();
    transient protected X500NameAttrMap attrMap;

    //========== CONSTRUCTOR ==================================

    /**
     * Construct an attribute from attribute type and attribute value
     *
     * @param oid the object identifier of the attribute type
     * @param value the value string
     */
    public Attribute(ObjectIdentifier oid, String value)
            throws IOException {

        //pre-condition verification
        if ((oid == null) || (value == null))
            throw new IOException("Invalid Input - null passed");

        attrMap = X500NameAttrMap.getDefault();
        this.oid = oid;
        valueSet.addElement(value);
    }

    /**
     * Construct an attribute from attribute type and attribute values
     *
     * @param oid the object identifier of the attribute type
     * @param values String value vector
     */
    public Attribute(ObjectIdentifier oid, Vector<String> values)
            throws IOException {

        //pre-condition verification
        if ((oid == null) || (values == null))
            throw new IOException("Invalid Input - null passed");

        attrMap = X500NameAttrMap.getDefault();
        this.oid = oid;

        //copy the value into the valueSet list
        Enumeration<String> vals = values.elements();
        while (vals.hasMoreElements()) {
            valueSet.addElement(vals.nextElement());
        }
    }

    /**
     * Construct an attribute from attribute type and attribute values
     *
     * @param oid attribute type string CN,OU,O,C,L,TITLE,ST,STREET,UID,MAIL,E,DC
     * @param values String value vector
     */
    public Attribute(String attr, Vector<String> values)
            throws IOException {

        //pre-condition verification
        if ((attr == null) || (values == null))
            throw new IOException("Invalid Input - null passed");

        ObjectIdentifier identifier = null;
        try {
            identifier = new ObjectIdentifier(attr);
        } catch (Exception e) {
        }

        ObjectIdentifier id = identifier;
        if (identifier == null) {
            attrMap = X500NameAttrMap.getDefault();
            id = attrMap.getOid(attr);
            if (id == null)
                throw new IOException("Attr is not supported - does not contain in attr map");
        }
        this.oid = id;

        //copy the value into the valueSet list
        Enumeration<String> vals = values.elements();
        while (vals.hasMoreElements()) {
            valueSet.addElement(vals.nextElement());
        }
    }

    /**
     * Construct an attribute from a der encoded object. This der
     * der encoded value should represent the attribute object.
     *
     * @param value the attribute object in der encode form.
     */
    public Attribute(DerValue val)
            throws IOException {

        //pre-condition verification
        if (val == null)
            throw new IOException("Invalid Input - null passed");

        attrMap = X500NameAttrMap.getDefault();

        decodeThis(val);

    }

    //========== PUBLIC METHODS ==================================

    /**
     * Returns the OID in the Attribute.
     *
     * @return the ObjectIdentifier in this Attribute.
     */
    public ObjectIdentifier getOid() {
        return oid;
    }

    /**
     * Returns enumeration of values in this attribute.
     *
     * @return Enumeration of values of this Attribute.
     */
    public Enumeration<String> getValues() {
        if (valueSet == null)
            return null;
        return valueSet.elements();
    }

    /**
     * Encodes the Attribute to a Der output stream.
     * Attribute are encoded as a SEQUENCE of two elements.
     *
     * @param out The Der output stream.
     */
    public void encode(DerOutputStream out) throws IOException {
        encodeThis(out);
    }

    /**
     * DER encode this object onto an output stream.
     * Implements the <code>DerEncoder</code> interface.
     *
     * @param out
     *            the output stream on which to write the DER encoding.
     *
     * @exception IOException on encoding error.
     */
    public void derEncode(OutputStream out) throws IOException {
        encodeThis(out);
    }

    /**
     * Prints a string version of this extension.
     */
    public String toString() {
        String theoid = "Attribute: " + oid + "\n";
        StringBuffer values = new StringBuffer("Values: ");
        Enumeration<String> n = valueSet.elements();
        if (n.hasMoreElements()) {
            values.append(n.nextElement());
            while (n.hasMoreElements())
                values.append("," + n.nextElement());
        }
        return theoid + values.toString() + "\n";
    }

    //========== PRIVATE METHODS ==================================

    //encode the attribute object
    private void encodeThis(OutputStream out)
            throws IOException {
        try (DerOutputStream tmp2 = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            tmp.putOID(oid);
            encodeValueSet(tmp);
            tmp2.write(DerValue.tag_Sequence, tmp);
            out.write(tmp2.toByteArray());
        }
    }

    //encode the attribute object
    private void encodeValueSet(OutputStream out)
            throws IOException {
        try (DerOutputStream tmp2 = new DerOutputStream()) {
            DerOutputStream tmp = new DerOutputStream();

            //get the attribute converter
            AVAValueConverter converter = attrMap.getValueConverter(oid);
            if (converter == null) {
                converter = new GenericValueConverter();
                //throw new IOException("Converter not found: unsupported attribute type");
            }

            //loop through all the values and encode
            Enumeration<String> vals = valueSet.elements();
            while (vals.hasMoreElements()) {
                String val = vals.nextElement();
                DerValue derobj = converter.getValue(val);
                derobj.encode(tmp);
            }

            tmp2.write(DerValue.tag_SetOf, tmp);
            out.write(tmp2.toByteArray());
        }
    }

    //decode the attribute object
    private void decodeThis(DerValue val)
            throws IOException {

        //pre-condition verification
        if (val == null) {
            throw new IOException("Invalid Input - null passed.");
        }

        if (val.tag != DerValue.tag_Sequence) {
            throw new IOException("Invalid encoding for Attribute.");
        }

        if (val.data.available() == 0) {
            throw new IOException("No data available in "
                                   + "passed DER encoded value.");
        }
        this.oid = val.data.getDerValue().getOID();

        if (val.data.available() == 0) {
            throw new IOException("Invalid encoding for Attribute - value missing");
        }
        decodeValueSet(val.data.getDerValue());

        if (this.oid == null)
            throw new IOException("Invalid encoding for Attribute - OID missing");

    }

    //decode the attribute value set
    private void decodeValueSet(DerValue val)
            throws IOException {
        //pre-condition verification
        if (val == null) {
            throw new IOException("Invalid Input - null passed.");
        }

        AVAValueConverter converter = attrMap.getValueConverter(this.oid);
        if (converter == null) {
            converter = new GenericValueConverter();
            //throw new IOException("Attribute is not supported - not in attr map");
        }

        if (val.tag != DerValue.tag_SetOf) {
            throw new IOException("Invalid encoding for Attribute Value Set.");
        }

        if (val.data.available() == 0) {
            throw new IOException("No data available in "
                                   + "passed DER encoded attribute value set.");
        }

        //get the value set
        while (val.data.available() != 0) {
            DerValue value = val.data.getDerValue();
            valueSet.addElement(converter.getAsString(value));
        }
    }

}
