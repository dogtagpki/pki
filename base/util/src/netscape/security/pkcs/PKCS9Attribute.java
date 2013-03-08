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
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Hashtable;

import netscape.security.util.DerEncoder;
import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertificateExtensions;

/**
 * Class supporting any PKCS9 attribute except
 * ExtendedCertificateAttribute. Supports DER decoding and access to
 * attribute values, but not DER encoding or setting of values.
 *
 * @version 1.2 97/12/10
 * @author Douglas Hoover
 */
public class PKCS9Attribute implements DerEncoder {

    /*
     * OIDs of PKCS #9 attribute types.
     */
    private static final String RSADSI_str = "1.2.840.113549";
    private static final String PKCS_str = RSADSI_str + ".1";
    private static final String PKCS9_str = PKCS_str + ".9";

    /**
     * Array of attribute OIDs defined in PKCS9, by number.
     */
    static final ObjectIdentifier[] PKCS9_OIDS =
            //new ObjectIdentifier[10];
            // There are some Obsolete(?) attribute identifiers.
            // This is mainly for extensionRequest (14) in pkcs10.
            // We just add the other 4 as by products.
            new ObjectIdentifier[15];

    static { // static initializer for PKCS9_OIDS
        for (int i = 1; i < PKCS9_OIDS.length; i++) {
            PKCS9_OIDS[i] = new ObjectIdentifier(PKCS9_str + "." + i);
        }
    }

    public static final ObjectIdentifier EMAIL_ADDRESS_OID = PKCS9_OIDS[1];
    public static final ObjectIdentifier UNSTRUCTURED_NAME_OID = PKCS9_OIDS[2];
    public static final ObjectIdentifier CONTENT_TYPE_OID = PKCS9_OIDS[3];
    public static final ObjectIdentifier MESSAGE_DIGEST_OID = PKCS9_OIDS[4];
    public static final ObjectIdentifier SIGNING_TIME_OID = PKCS9_OIDS[5];
    public static final ObjectIdentifier COUNTERSIGNATURE_OID = PKCS9_OIDS[6];
    public static final ObjectIdentifier CHALLENGE_PASSWORD_OID = PKCS9_OIDS[7];
    public static final ObjectIdentifier UNSTRUCTURED_ADDRESS_OID = PKCS9_OIDS[8];
    public static final ObjectIdentifier EXTENDED_CERTIFICATE_ATTRIBUTES_OID = PKCS9_OIDS[9];

    public static final ObjectIdentifier ISSUER_AND_SERIALNUMBER_OID = PKCS9_OIDS[10];
    public static final ObjectIdentifier PASSWORD_CHECK_OID = PKCS9_OIDS[11];
    public static final ObjectIdentifier PUBLIC_KEY_OID = PKCS9_OIDS[12];
    public static final ObjectIdentifier SIGNING_DESCRIPTION_OID = PKCS9_OIDS[13];
    public static final ObjectIdentifier EXTENSION_REQUEST_OID = PKCS9_OIDS[14];

    public static final String EMAIL_ADDRESS_STR = "EmailAddress";
    public static final String UNSTRUCTURED_NAME_STR = "UnstructuredName";
    public static final String CONTENT_TYPE_STR = "ContentType";
    public static final String MESSAGE_DIGEST_STR = "MessageDigest";
    public static final String SIGNING_TIME_STR = "SigningTime";
    public static final String COUNTERSIGNATURE_STR = "Countersignature";
    public static final String CHALLENGE_PASSWORD_STR = "ChallengePassword";
    public static final String UNSTRUCTURED_ADDRESS_STR = "UnstructuredAddress";
    public static final String EXTENDED_CERTIFICATE_ATTRIBUTES_STR = "ExtendedCertificateAttributes";

    public static final String ISSUER_AND_SERIALNUMBER_STR = "IssuerAndSerialNumber";
    public static final String PASSWORD_CHECK_STR = "PasswordCheck";
    public static final String PUBLIC_KEY_STR = "PublicKey";
    public static final String SIGNING_DESCRIPTION_STR = "SigningDescription";
    public static final String EXTENSION_REQUEST_STR = "ExtensionRequest";

    /**
     * Hashtable mapping names and variant names of supported
     * attributes to their OIDs. This table contains all name forms
     * that occur in PKCS9, in lower case.
     */
    private static final Hashtable<String, ObjectIdentifier> NAME_OID_TABLE = new Hashtable<String, ObjectIdentifier>(
            28);

    static { // static initializer for PCKS9_NAMES
        NAME_OID_TABLE.put("emailaddress", PKCS9_OIDS[1]);
        NAME_OID_TABLE.put("unstructuredname", PKCS9_OIDS[2]);
        NAME_OID_TABLE.put("contenttype", PKCS9_OIDS[3]);
        NAME_OID_TABLE.put("messagedigest", PKCS9_OIDS[4]);
        NAME_OID_TABLE.put("signingtime", PKCS9_OIDS[5]);
        NAME_OID_TABLE.put("countersignature", PKCS9_OIDS[6]);
        NAME_OID_TABLE.put("challengepassword", PKCS9_OIDS[7]);
        NAME_OID_TABLE.put("unstructuredaddress", PKCS9_OIDS[8]);
        NAME_OID_TABLE.put("extendedcertificateattributes", PKCS9_OIDS[9]);

        NAME_OID_TABLE.put("issuerandserialNumber", PKCS9_OIDS[10]);
        NAME_OID_TABLE.put("passwordcheck", PKCS9_OIDS[11]);
        NAME_OID_TABLE.put("publickey", PKCS9_OIDS[12]);
        NAME_OID_TABLE.put("signingdescription", PKCS9_OIDS[13]);
        NAME_OID_TABLE.put("extensionrequest", PKCS9_OIDS[14]);
    };

    /**
     * Hashtable mapping attribute OIDs defined in PKCS9 to the
     * corresponding attribute value type.
     */
    private static final Hashtable<ObjectIdentifier, String> OID_NAME_TABLE = new Hashtable<ObjectIdentifier, String>(
            14);
    static {
        OID_NAME_TABLE.put(PKCS9_OIDS[1], EMAIL_ADDRESS_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[2], UNSTRUCTURED_NAME_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[3], CONTENT_TYPE_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[4], MESSAGE_DIGEST_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[5], SIGNING_TIME_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[6], COUNTERSIGNATURE_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[7], CHALLENGE_PASSWORD_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[8], UNSTRUCTURED_ADDRESS_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[9], EXTENDED_CERTIFICATE_ATTRIBUTES_STR);

        OID_NAME_TABLE.put(PKCS9_OIDS[10], ISSUER_AND_SERIALNUMBER_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[11], PASSWORD_CHECK_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[12], PUBLIC_KEY_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[13], SIGNING_DESCRIPTION_STR);
        OID_NAME_TABLE.put(PKCS9_OIDS[14], EXTENSION_REQUEST_STR);
    }

    /**
     * Acceptable ASN.1 tags for DER encodings of values of PKCS9
     * attributes, by index in <code>PKCS9_OIDS</code>.
     * Sets of acceptable tags are represented as arrays.
     */
    private static final Byte[][] PKCS9_VALUE_TAGS = {
            null,
            { Byte.valueOf(DerValue.tag_IA5String) }, // EMailAddress
            { Byte.valueOf(DerValue.tag_IA5String) }, // UnstructuredName
            { Byte.valueOf(DerValue.tag_ObjectId) }, // ContentType
            { Byte.valueOf(DerValue.tag_OctetString) }, // MessageDigest
            { Byte.valueOf(DerValue.tag_UtcTime) }, // SigningTime
            { Byte.valueOf(DerValue.tag_Sequence) }, // Countersignature
            { Byte.valueOf(DerValue.tag_PrintableString),
                    Byte.valueOf(DerValue.tag_T61String) }, // ChallengePassword
            { Byte.valueOf(DerValue.tag_PrintableString),
                    Byte.valueOf(DerValue.tag_T61String) }, // UnstructuredAddress
            { Byte.valueOf(DerValue.tag_SetOf) }, // ExtendedCertificateAttributes

            null, //IssuerAndSerialNumber
            null, //PasswordCheck
            null, //PublicKey
            null, //SigningDescription
            { Byte.valueOf(DerValue.tag_Sequence) } //ExtensionRequest
            };

    /**
     * Class types required for values for a given PKCS9
     * attribute type.
     *
     * <P>
     * The following table shows the correspondence between attribute types and value component classes.
     *
     * <P>
     * <TABLE BORDER CELLPADDING=8 ALIGN=CENTER>
     *
     * <TR>
     * <TH>OID</TH>
     * <TH>Attribute Type Name</TH>
     * <TH>Kind</TH>
     * <TH>Value Class</TH>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.1</TD>
     * <TD>EmailAddress</TD>
     * <TD>Multiple-valued</TD>
     * <TD><code>String[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.2</TD>
     * <TD>UnstructuredName</TD>
     * <TD>Multiple-valued</TD>
     * <TD><code>String</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.3</TD>
     * <TD>ContentType</TD>
     * <TD>Single-valued</TD>
     * <TD><code>ObjectIdentifier</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.4</TD>
     * <TD>MessageDigest</TD>
     * <TD>Single-valued</TD>
     * <TD><code>byte[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.5</TD>
     * <TD>SigningTime</TD>
     * <TD>Single-valued</TD>
     * <TD><code>Date</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.6</TD>
     * <TD>Countersignature</TD>
     * <TD>Multiple-valued</TD>
     * <TD><code>SignerInfo</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.7</TD>
     * <TD>ChallengePassword</TD>
     * <TD>Single-valued</TD>
     * <TD><code>String</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.8</TD>
     * <TD>UnstructuredAddress</TD>
     * <TD>Single-valued</TD>
     * <TD><code>String</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.9</TD>
     * <TD>ExtendedCertificateAttributes</TD>
     * <TD>Multiple-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.10</TD>
     * <TD>IssuerAndSerialNumber</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.11</TD>
     * <TD>PasswordCheck</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.12</TD>
     * <TD>PublicKey</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.13</TD>
     * <TD>SigningDescription</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.14</TD>
     * <TD>ExtensionRequest</TD>
     * <TD>Single-valued</TD>
     * <TD><code>Sequence</code></TD>
     * </TR>
     *
     * </TABLE>
     */
    private static final Class<?>[] VALUE_CLASSES = new Class[15];

    static {
        VALUE_CLASSES[0] = null; // not used
        VALUE_CLASSES[1] = String[].class; // EMailAddress
        VALUE_CLASSES[2] = String[].class; // UnstructuredName
        VALUE_CLASSES[3] = ObjectIdentifier.class; // ContentType
        VALUE_CLASSES[4] = byte[].class; // MessageDigest (byte[])
        VALUE_CLASSES[5] = Date.class; // SigningTime
        VALUE_CLASSES[6] = SignerInfo[].class; // Countersignature
        VALUE_CLASSES[7] = String.class; // ChallengePassword
        VALUE_CLASSES[8] = String[].class; // UnstructuredAddress
        VALUE_CLASSES[9] = null; // ExtendedCertificateAttributes

        VALUE_CLASSES[10] = null; // IssuerAndSerialNumber
        VALUE_CLASSES[11] = null; // PasswordCheck
        VALUE_CLASSES[12] = null; // PublicKey
        VALUE_CLASSES[13] = null; // SigningDescription
        VALUE_CLASSES[14] = CertificateExtensions.class; // ExtensionRequest
    }

    /**
     * Array indicating which PKCS9 attributes are single-valued,
     * by index in <code>PKCS9_OIDS</code>.
     */
    private static final boolean[] SINGLE_VALUED =
    { false,
            false, // EMailAddress
            false, // UnstructuredName
            true, // ContentType
            true, // MessageDigest
            true, // SigningTime
            false, // Countersignature
            true, // ChallengePassword
            false, // UnstructuredAddress
            false, // ExtendedCertificateAttributes

            true, // IssuerAndSerialNumber
            true, // PasswordCheck
            true, // PublicKey
            true, // SigningDescription
            true // ExtensionRequest
    };

    /**
     * The OID of this attribute is <code>PKCS9_OIDS[index]</code>.
     */
    private int index;

    /**
     * Value set of this attribute. Its class is given by <code>VALUE_CLASSES[index]</code>.
     */
    private Object value;

    /**
     * Construct an attribute object from the attribute's OID and
     * value. If the attribute is single-valued, provide only one
     * value. If the attribute is
     * multiple-valued, provide an array containing all the values.
     * Arrays of length zero are accepted, though probably useless.
     *
     * <P>
     * The following table gives the class that <code>value</code> must have for a given attribute.
     *
     * <P>
     * <TABLE BORDER CELLPADDING=8 ALIGN=CENTER>
     *
     * <TR>
     * <TH>OID</TH>
     * <TH>Attribute Type Name</TH>
     * <TH>Kind</TH>
     * <TH>Value Class</TH>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.1</TD>
     * <TD>EmailAddress</TD>
     * <TD>Multiple-valued</TD>
     * <TD><code>String[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.2</TD>
     * <TD>UnstructuredName</TD>
     * <TD>Multiple-valued</TD>
     * <TD><code>String[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.3</TD>
     * <TD>ContentType</TD>
     * <TD>Single-valued</TD>
     * <TD><code>ObjectIdentifier</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.4</TD>
     * <TD>MessageDigest</TD>
     * <TD>Single-valued</TD>
     * <TD><code>byte[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.5</TD>
     * <TD>SigningTime</TD>
     * <TD>Single-valued</TD>
     * <TD><code>Date</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.6</TD>
     * <TD>Countersignature</TD>
     * <TD>Multiple-valued</TD>
     * <TD><code>SignerInfo[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.7</TD>
     * <TD>ChallengePassword</TD>
     * <TD>Single-valued</TD>
     * <TD><code>String</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.8</TD>
     * <TD>UnstructuredAddress</TD>
     * <TD>Single-valued</TD>
     * <TD><code>String[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.9</TD>
     * <TD>ExtendedCertificateAttributes</TD>
     * <TD>Multiple-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.10</TD>
     * <TD>IssuerAndSerialNumber</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.11</TD>
     * <TD>PasswordCheck</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.12</TD>
     * <TD>PublicKey</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.13</TD>
     * <TD>SigningDescription</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.14</TD>
     * <TD>ExtensionRequest</TD>
     * <TD>Single-valued</TD>
     * <TD><code>Sequence</code></TD>
     * </TR>
     *
     * </TABLE>
     */
    public PKCS9Attribute(ObjectIdentifier oid, Object value)
            throws IllegalArgumentException {

        init(oid, value);
    }

    /**
     * Construct an attribute object from the attribute's name and
     * value. If the attribute is single-valued, provide only one
     * value. If the attribute is
     * multiple-valued, provide an array containing all the values.
     * Arrays of length zero are accepted, though probably useless.
     *
     * <P>
     * The following table gives the class that <code>value</code> must have for a given attribute. Reasonable variants
     * of these attributes are accepted; in particular, case does not matter.
     *
     * <P>
     * <TABLE BORDER CELLPADDING=8 ALIGN=CENTER>
     *
     * <TR>
     * <TH>OID</TH>
     * <TH>Attribute Type Name</TH>
     * <TH>Kind</TH>
     * <TH>Value Class</TH>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.1</TD>
     * <TD>EmailAddress</TD>
     * <TD>Multiple-valued</TD>
     * <TD><code>String[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.2</TD>
     * <TD>UnstructuredName</TD>
     * <TD>Multiple-valued</TD>
     * <TD><code>String[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.3</TD>
     * <TD>ContentType</TD>
     * <TD>Single-valued</TD>
     * <TD><code>ObjectIdentifier</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.4</TD>
     * <TD>MessageDigest</TD>
     * <TD>Single-valued</TD>
     * <TD><code>byte[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.5</TD>
     * <TD>SigningTime</TD>
     * <TD>Single-valued</TD>
     * <TD><code>Date</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.6</TD>
     * <TD>Countersignature</TD>
     * <TD>Multiple-valued</TD>
     * <TD><code>SignerInfo[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.7</TD>
     * <TD>ChallengePassword</TD>
     * <TD>Single-valued</TD>
     * <TD><code>String</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.8</TD>
     * <TD>UnstructuredAddress</TD>
     * <TD>Single-valued</TD>
     * <TD><code>String[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.9</TD>
     * <TD>ExtendedCertificateAttributes</TD>
     * <TD>Multiple-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.10</TD>
     * <TD>IssuerAndSerialNumber</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.11</TD>
     * <TD>PasswordCheck</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.12</TD>
     * <TD>PublicKey</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.13</TD>
     * <TD>SigningDescription</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.14</TD>
     * <TD>ExtensionRequest</TD>
     * <TD>Single-valued</TD>
     * <TD><code>Sequence</code></TD>
     * </TR>
     *
     * </TABLE>
     *
     * @exception IllegalArgumentException
     *                if the <code>name</code> is not recognized of the <code>value</code> has the wrong type.
     */
    public PKCS9Attribute(String name, Object value)
            throws IllegalArgumentException {
        ObjectIdentifier oid = getOID(name);

        if (oid == null)
            throw new IllegalArgumentException(
                    "Unrecognized attribute name " + name +
                            " constructing PKCS9Attribute.");

        init(oid, value);
    }

    private void init(ObjectIdentifier oid, Object value)
            throws IllegalArgumentException {

        index = indexOf(oid, PKCS9_OIDS, 1);

        if (index == -1)
            throw new IllegalArgumentException(
                    "Unsupported OID " + oid +
                            " constructing PKCS9Attribute.");

        if (!VALUE_CLASSES[index].isInstance(value))
            throw new IllegalArgumentException(
                    "Wrong value class " +
                            " for attribute " + oid +
                            " constructing PKCS9Attribute; was " +
                            value.getClass().toString() + ", should be " +
                            VALUE_CLASSES[index].toString());

        this.value = value;
    }

    /**
     * Construct a PKCS9Attribute from its encoding on an input
     * stream.
     *
     * @exception IOException on parsing error.
     */
    public PKCS9Attribute(DerValue derVal) throws IOException {

        decode(derVal);
    }

    /**
     * Decode a PKCS9 attribute.
     *
     * @param val
     *            the DerValue representing the DER encoding of the attribute.
     */
    private void decode(DerValue derVal) throws IOException {
        DerInputStream derIn = new DerInputStream(derVal.toByteArray());
        DerValue[] val = derIn.getSequence(2);

        if (derIn.available() != 0)
            throw new IOException("Excess data parsing PKCS9Attribute");

        if (val.length != 2)
            throw new IOException("PKCS9Attribute doesn't have two components");

        DerValue[] elems;

        // get the oid
        ObjectIdentifier oid = val[0].getOID();

        index = indexOf(oid, PKCS9_OIDS, 1);
        Byte tag;

        if (index == -1)
            throw new IOException("Invalid OID for PKCS9 attribute: " +
                    oid);

        elems = new DerInputStream(val[1].toByteArray()).getSet(1);

        // check single valued have only one value
        if (SINGLE_VALUED[index] && elems.length > 1)
            throwSingleValuedException();

        // check for illegal element tags
        for (int i = 0; i < elems.length; i++) {
            tag = Byte.valueOf(elems[i].tag);

            if (indexOf(tag, PKCS9_VALUE_TAGS[index], 0) == -1)
                throwTagException(tag);
        }

        switch (index) {
        case 1: // email address
        case 2: // unstructured name
        case 8: // unstructured address
        { // open scope
            String[] values = new String[elems.length];

            for (int i = 0; i < elems.length; i++)
                values[i] = elems[i].getAsString();
            value = values;
        } // close scope
            break;

        case 3: // content type
            value = elems[0].getOID();
            break;

        case 4: // message digest
            value = elems[0].getOctetString();
            break;

        case 5: // signing time
            value = (new DerInputStream(elems[0].toByteArray())).getUTCTime();
            break;

        case 6: // countersignature
        { // open scope
            SignerInfo[] values = new SignerInfo[elems.length];
            for (int i = 0; i < elems.length; i++)
                values[i] =
                        new SignerInfo(elems[i].toDerInputStream());
            value = values;
        } // close scope
            break;

        case 7: // challenge password
            value = elems[0].getAsString();
            break;

        case 9: // extended-certificate attribute -- not
            // supported
            throw new IOException("PKCS9 extended-certificate " +
                    "attribute not supported.");

        case 10: // IssuerAndSerialNumber attribute -- not
            // supported
            throw new IOException("PKCS9 IssuerAndSerialNumber " +
                    "attribute not supported.");

        case 11: // passwordCheck attribute -- not
            // supported
            throw new IOException("PKCS9 passwordCheck " +
                    "attribute not supported.");
        case 12: // PublicKey attribute -- not
            // supported
            throw new IOException("PKCS9 PublicKey " +
                    "attribute not supported.");
        case 13: // SigningDescription attribute -- not
            // supported
            throw new IOException("PKCS9 SigningDescription " +
                    "attribute not supported.");
        case 14: // ExtensionRequest attribute
            value =
                    new CertificateExtensions(elems[0].toDerInputStream());

            // break unnecessary

        default: // can't happen
        }

    }

    /**
     * Write the DER encoding of this attribute to an output stream.
     *
     * <P>
     * N.B.: This method always encodes values of ChallengePassword and UnstructuredAddress attributes as ASN.1
     * <code>PrintableString</code>s, without checking whether they should be encoded as <code>T61String</code>s.
     */
    public void derEncode(OutputStream out) throws IOException {
        try (DerOutputStream temp = new DerOutputStream();
             DerOutputStream temp2 = new DerOutputStream();
             DerOutputStream derOut = new DerOutputStream()) {
            temp.putOID(getOID());
            switch (index) {
            case 1: // email address
            case 2: // unstructured name
            { // open scope
                String[] values = (String[]) value;
                DerOutputStream[] temps = new
                        DerOutputStream[values.length];

                for (int i = 0; i < values.length; i++) {
                    temps[i] = new DerOutputStream();

                    temps[i].putIA5String(values[i]);
                }
                temp.putOrderedSetOf(DerValue.tag_Set, temps);
            } // close scope
                break;

            case 3: // content type
            {
                temp2.putOID((ObjectIdentifier) value);
                temp.write(DerValue.tag_Set, temp2.toByteArray());
            }
                break;

            case 4: // message digest
            {
                temp2.putOctetString((byte[]) value);
                temp.write(DerValue.tag_Set, temp2.toByteArray());
            }
                break;

            case 5: // signing time
            {
                temp2.putUTCTime((Date) value);
                temp.write(DerValue.tag_Set, temp2.toByteArray());
            }
                break;

            case 6: // countersignature
                temp.putOrderedSetOf(DerValue.tag_Set, (DerEncoder[]) value);
                break;

            case 7: // challenge password
            {
                temp2.putPrintableString((String) value);
                temp.write(DerValue.tag_Set, temp2.toByteArray());
            }
                break;

            case 8: // unstructured address
            { // open scope
                String[] values = (String[]) value;
                DerOutputStream[] temps = new
                        DerOutputStream[values.length];

                for (int i = 0; i < values.length; i++) {
                    temps[i] = new DerOutputStream();

                    temps[i].putPrintableString(values[i]);
                }
                temp.putOrderedSetOf(DerValue.tag_Set, temps);
            } // close scope
                break;

            case 9: // extended-certificate attribute -- not
                // supported
                throw new IOException("PKCS9 extended-certificate " +
                        "attribute not supported.");

            case 10: // IssuerAndSerialNumber attribute -- not
                // supported
                throw new IOException("PKCS9 IssuerAndSerialNumber " +
                        "attribute not supported.");

            case 11: // passwordCheck attribute -- not
                // supported
                throw new IOException("PKCS9 passwordCheck " +
                        "attribute not supported.");
            case 12: // PublicKey attribute -- not
                // supported
                throw new IOException("PKCS9 PublicKey " +
                        "attribute not supported.");
            case 13: // SigningDescription attribute -- not
                // supported
                throw new IOException("PKCS9 SigningDescription " +
                        "attribute not supported.");
            case 14: // ExtensionRequest attribute
                try {
                    //temp2.putSequence((CertificateExtensions) value);
                    ((CertificateExtensions) value).encode(temp2);
                    temp.write(DerValue.tag_Sequence, temp2.toByteArray());
                } catch (CertificateException e) {
                    throw new IOException("PKCS9 extension attributes not encoded");
                }

                // break unnecessary
            default: // can't happen
            }

            derOut.write(DerValue.tag_Sequence, temp.toByteArray());

            out.write(derOut.toByteArray());
        }
    }

    /**
     * Get the value of this attribute. If the attribute is
     * single-valued, return just the one value. If the attribute is
     * multiple-valued, return an array containing all the values.
     * It is possible for this array to be of length 0.
     *
     * <P>
     * The following table gives the class of the value returned, depending on the type of this attribute.
     *
     * <P>
     * <TABLE BORDER CELLPADDING=8 ALIGN=CENTER>
     *
     * <TR>
     * <TH>OID</TH>
     * <TH>Attribute Type Name</TH>
     * <TH>Kind</TH>
     * <TH>Value Class</TH>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.1</TD>
     * <TD>EmailAddress</TD>
     * <TD>Multiple-valued</TD>
     * <TD><code>String[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.2</TD>
     * <TD>UnstructuredName</TD>
     * <TD>Multiple-valued</TD>
     * <TD><code>String[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.3</TD>
     * <TD>ContentType</TD>
     * <TD>Single-valued</TD>
     * <TD><code>ObjectIdentifier</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.4</TD>
     * <TD>MessageDigest</TD>
     * <TD>Single-valued</TD>
     * <TD><code>byte[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.5</TD>
     * <TD>SigningTime</TD>
     * <TD>Single-valued</TD>
     * <TD><code>Date</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.6</TD>
     * <TD>Countersignature</TD>
     * <TD>Multiple-valued</TD>
     * <TD><code>SignerInfo[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.7</TD>
     * <TD>ChallengePassword</TD>
     * <TD>Single-valued</TD>
     * <TD><code>String</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.8</TD>
     * <TD>UnstructuredAddress</TD>
     * <TD>Single-valued</TD>
     * <TD><code>String[]</code></TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.9</TD>
     * <TD>ExtendedCertificateAttributes</TD>
     * <TD>Multiple-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.10</TD>
     * <TD>IssuerAndSerialNumber</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.11</TD>
     * <TD>PasswordCheck</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.12</TD>
     * <TD>PublicKey</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.13</TD>
     * <TD>SigningDescription</TD>
     * <TD>Single-valued</TD>
     * <TD>(not supported)</TD>
     * </TR>
     *
     * <TR>
     * <TD>1.2.840.113549.1.9.14</TD>
     * <TD>ExtensionRequest</TD>
     * <TD>Single-valued</TD>
     * <TD><code>Sequence</code></TD>
     * </TR>
     *
     * </TABLE>
     *
     */
    public Object getValue() {
        return value;
    }

    /**
     * Show whether this attribute is single-valued.
     */
    public boolean isSingleValued() {
        return SINGLE_VALUED[index];
    }

    /**
     * Return the OID of this attribute.
     */
    public ObjectIdentifier getOID() {
        return PKCS9_OIDS[index];
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return OID_NAME_TABLE.get(PKCS9_OIDS[index]);
    }

    /**
     * Return the OID for a given attribute name or null if we don't recognize
     * the name.
     */
    public static ObjectIdentifier getOID(String name) {
        return NAME_OID_TABLE.get(name.toLowerCase());
    }

    /**
     * Return the attribute name for a given OID or null if we don't recognize
     * the oid.
     */
    public static String getName(ObjectIdentifier oid) {
        return OID_NAME_TABLE.get(oid);
    }

    /**
     * Returns a string representation of this attribute.
     */
    public String toString() {
        StringBuffer buf = new StringBuffer(100);

        buf.append("[");

        buf.append(OID_NAME_TABLE.get(PKCS9_OIDS[index]));
        buf.append(": ");

        if (SINGLE_VALUED[index]) {
            if (value instanceof byte[]) { // special case for octet string
                netscape.security.util.PrettyPrintFormat pp =
                        new netscape.security.util.PrettyPrintFormat(" ", 20);
                String valuebits = pp.toHexString(((byte[]) value));
                buf.append(valuebits);
            } else {
                buf.append(value.toString());
            }
            buf.append("]");
            return buf.toString();
        } else { // multiple-valued
            boolean first = true;
            Object[] values = (Object[]) value;

            for (int j = 0; j < values.length; j++) {
                if (first)
                    first = false;
                else
                    buf.append(", ");

                buf.append(values[j].toString());
            }
            return buf.toString();
        }
    }

    /**
     * Beginning the search at <code>start</code>, find the first
     * index <code>i</code> such that <code>a[i] = obj</code>.
     *
     * @return the index, if found, and -1 otherwise.
     */
    static int indexOf(Object obj, Object[] a, int start) {
        for (int i = start; i < a.length; i++) {
            if (obj.equals(a[i]))
                return i;
        }
        return -1;
    }

    /**
     * Throw an exception when there are multiple values for
     * a single-valued attribute.
     */
    private void throwSingleValuedException() throws IOException {
        throw new IOException("Single-value attribute " +
                  getOID() + " (" + getName() + ")" +
                  " has multiple values.");
    }

    /**
     * Throw an exception when the tag on a value encoding is
     * wrong for the attribute whose value it is.
     */
    private void throwTagException(Byte tag)
            throws IOException {
        Byte[] expectedTags = PKCS9_VALUE_TAGS[index];
        StringBuffer msg = new StringBuffer(100);
        msg.append("Value of attribute ");
        msg.append(getOID().toString());
        msg.append(" (");
        msg.append(getName());
        msg.append(") has wrong tag: ");
        msg.append(tag.toString());
        msg.append(".  Expected tags: ");

        msg.append(expectedTags[0].toString());

        for (int i = 1; i < expectedTags.length; i++) {
            msg.append(", ");
            msg.append(expectedTags[i].toString());
        }
        msg.append(".");
        throw new IOException(msg.toString());
    }

}
