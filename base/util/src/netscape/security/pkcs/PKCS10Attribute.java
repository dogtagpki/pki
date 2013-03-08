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
import java.io.OutputStream;
import java.io.Serializable;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.cert.CertificateException;

import netscape.security.util.DerEncoder;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.ACertAttrSet;
import netscape.security.x509.CertAttrSet;
import netscape.security.x509.Extensions;
import netscape.security.x509.OIDMap;

/**
 * Represent a PKCS Attribute.
 *
 * <p>
 * Attributes are addiitonal attributes which can be inserted in a PKCS certificate request. For example a
 * "Driving License Certificate" could have the driving license number as a attribute.
 *
 * <p>
 * Attributes are represented as a sequence of the attribute identifier (Object Identifier) and a set of DER encoded
 * attribute values. The current implementation only supports one value per attribute.
 *
 * ASN.1 definition of Attribute:
 *
 * <pre>
 * Attribute :: SEQUENCE {
 *    type    AttributeValue,
 *    values  SET OF AttributeValue
 * }
 * AttributeValue ::= ANY
 * </pre>
 *
 * @author Amit Kapoor
 * @author Hemma Prafullchandra
 * @version 1.13
 */
public class PKCS10Attribute implements DerEncoder, Serializable {
    private static final long serialVersionUID = 2002480042340316170L;
    protected ObjectIdentifier attributeId = null;
    protected CertAttrSet attributeValue = null;

    /**
     * Default constructor. Used only by sub-classes.
     */
    public PKCS10Attribute() {
    }

    /**
     * Constructs an attribute from a DER encoded array of bytes.
     */
    public PKCS10Attribute(DerValue derVal) throws IOException {
        if (derVal.tag != DerValue.tag_Sequence) {
            throw new IOException("Sequence tag missing for PKCS10Attribute.");
        }

        DerInputStream in = derVal.toDerInputStream();
        // Object identifier
        attributeId = in.getOID();
        // System.out.println("attribute ID in pkcs10 "+attributeId.toString());

        // Rest of the stuff is attribute value(s), wrapped in a SET.
        // For now, assume there is only one attribute value present.
        DerValue[] inAttrValues = in.getSet(1);
        int attrValueNum = inAttrValues.length;
        if (attrValueNum > 1) {
            throw new IOException("More than one value per attribute not supported");
        }

        // Read the first attribute value
        DerValue inAttrValue = inAttrValues[0];

        if (attributeId.equals(PKCS9Attribute.EXTENSION_REQUEST_OID)) {
            //pkcs9 extensionAttr
            try {
                // remove the tag
                //DerValue dv = inAttrValue.data.getDerValue();
                // hack. toDerInputStream only gives one extension.
                DerInputStream fi = new DerInputStream(inAttrValue.toByteArray());
                attributeValue = new Extensions(fi);
                //CertificateExtensions(fi);
                return;
            } catch (Exception e) {
                throw new IOException(e.toString());
            }
        }
        byte[] val = inAttrValue.toByteArray();
        Class<?>[] params = { Object.class };
        try {
            @SuppressWarnings("unchecked")
            Class<CertAttrSet> extClass = (Class<CertAttrSet>) OIDMap.getClass(attributeId);
            if (extClass != null) {
                Constructor<CertAttrSet> cons = extClass.getConstructor(params);
                Object value = Array.newInstance(byte.class, val.length);
                for (int i = 0; i < val.length; i++) {
                    Array.setByte(value, i, val[i]);
                }
                Object[] passed = new Object[] { value };
                attributeValue = cons.newInstance(passed);
            } else {
                // attribute classes are usable for PKCS10 attributes.
                // this is used where the attributes are not actual
                // implemented extensions.
                attributeValue = new ACertAttrSet(inAttrValue);
            }
        } catch (InvocationTargetException invk) {
            throw new IOException(invk.getTargetException().getMessage());
        } catch (Exception e) {
            throw new IOException(e.toString());
        }
    }

    /**
     * Constructs an attribute from individual components of ObjectIdentifier
     * and the DER encoded value.
     *
     * @param attributeId the ObjectIdentifier of the attribute.
     * @param attributeValue the CertAttrSet.
     */
    public PKCS10Attribute(ObjectIdentifier attributeId,
                           CertAttrSet attributeValue) {
        this.attributeId = attributeId;
        this.attributeValue = attributeValue;
    }

    /**
     * Constructs an attribute from another attribute. To be used for
     * creating decoded subclasses.
     *
     * @param attr the attribute to create from.
     */
    public PKCS10Attribute(PKCS10Attribute attr) {
        this.attributeId = attr.attributeId;
        this.attributeValue = attr.attributeValue;
    }

    /**
     * Write the output to the DerOutputStream.
     *
     * @param out the OutputStream to write the attribute to.
     * @exception CertificateException on certificate encoding errors.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out)
            throws CertificateException, IOException {
        try (DerOutputStream tmp = new DerOutputStream()) {
            // Encode the attribute value
            DerOutputStream outAttrValue = new DerOutputStream();
            attributeValue.encode(outAttrValue);

            // Wrap the encoded attribute value into a SET
            DerValue outAttrValueSet = new DerValue(DerValue.tag_Set,
                    outAttrValue.toByteArray());

            // Create the attribute
            DerOutputStream outAttr = new DerOutputStream();
            outAttr.putOID(attributeId);
            outAttr.putDerValue(outAttrValueSet);

            // Wrap the OID and the set of attribute values into a SEQUENCE
            tmp.write(DerValue.tag_Sequence, outAttr);

            // write the results to out
            out.write(tmp.toByteArray());
        }
    }

    /**
     * DER encode this object onto an output stream.
     * Implements the <code>DerEncoder</code> interface.
     *
     * @param out
     *            the OutputStream on which to write the DER encoding.
     *
     * @exception IOException on encoding errors.
     */
    public void derEncode(OutputStream out) throws IOException {
        try {
            encode(out);
        } catch (CertificateException ce) {
            IOException ioe = new IOException(ce.toString());
            ioe.fillInStackTrace();
            throw ioe;
        }
    }

    /**
     * Returns the ObjectIdentifier of the attribute.
     */
    public ObjectIdentifier getAttributeId() {
        return (attributeId);
    }

    /**
     * Returns the attribute value as an byte array for further processing.
     */
    public CertAttrSet getAttributeValue() {
        return (attributeValue);
    }

    /**
     * Returns the attribute in user readable form.
     */
    public String toString() {
        String s = "AttributeId: " + attributeId.toString() + "\n";
        s += "AttributeValue: " + attributeValue.toString();

        return (s);
    }
}
