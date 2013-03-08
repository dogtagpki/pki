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
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.Vector;

import netscape.security.util.DerInputStream;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;

/**
 * Represent the CRL Hold Instruction Code Extension.
 *
 * <p>
 * The hold instruction code is a non-critical CRL entry extension that provides a registered instruction identifier
 * which indicates the action to be taken after encountering a certificate that has been placed on hold.
 *
 * @see Extension
 * @see CertAttrSet
 */

public class HoldInstructionExtension extends Extension
        implements CertAttrSet {

    /**
     *
     */
    private static final long serialVersionUID = -6706557233070964984L;
    /**
     * Attribute name.
     */
    public static final String NAME = "HoldInstruction";
    public static final String HOLD_INSTRUCTION = "value";

    /**
     * The Object Identifier for this extension.
     */
    public static final String OID = "2.5.29.23";

    public static final String NONE_HOLD_INSTR_OID_STR =
            "1.2.840.10040.2.1";
    public static final ObjectIdentifier NONE_HOLD_INSTR_OID =
            new ObjectIdentifier(NONE_HOLD_INSTR_OID_STR);

    public static final String CALL_ISSUER_HOLD_INSTR_OID_STR =
            "1.2.840.10040.2.2";
    public static final ObjectIdentifier CALL_ISSUER_HOLD_INSTR_OID =
            new ObjectIdentifier(CALL_ISSUER_HOLD_INSTR_OID_STR);

    public static final String REJECT_HOLD_INSTR_OID_STR =
            "1.2.840.10040.2.3";
    public static final ObjectIdentifier REJECT_HOLD_INSTR_OID =
            new ObjectIdentifier(REJECT_HOLD_INSTR_OID_STR);

    private ObjectIdentifier holdInstructionCodeOIDs[] = { NONE_HOLD_INSTR_OID,
                                                          CALL_ISSUER_HOLD_INSTR_OID,
                                                          REJECT_HOLD_INSTR_OID };
    private ObjectIdentifier holdInstructionCodeOID = null;

    private String holdInstructionDescription[] = { "None",
                                                   "Call Issuer",
                                                   "Reject" };

    static {
        try {
            OIDMap.addAttribute(HoldInstructionExtension.class.getName(),
                                OID, NAME);
        } catch (CertificateException e) {
        }
    }

    private int getHoldInstructionCodeFromOID(ObjectIdentifier oid) {
        for (int i = 0; i < holdInstructionCodeOIDs.length; i++) {
            if (oid.equals(holdInstructionCodeOIDs[i]))
                return (i + 1);
        }
        return 0;
    }

    private String getHoldInstructionDescription(ObjectIdentifier oid) {
        String description = "Invalid";
        if (oid != null) {
            int i = getHoldInstructionCodeFromOID(oid);
            if (i > 0 && i < 4)
                description = holdInstructionDescription[i - 1];
        }
        return (description);
    }

    // Encode this extension value
    private void encodeThis() throws IOException {
        if (holdInstructionCodeOID == null)
            throw new IOException("Unintialized hold instruction extension");

        try (DerOutputStream os = new DerOutputStream()) {
            os.putOID(holdInstructionCodeOID);
            this.extensionValue = os.toByteArray();
        }
    }

    /**
     * Create a HoldInstructionExtension with the date.
     * The criticality is set to false.
     *
     * @param code the value to be set for the extension.
     */
    public HoldInstructionExtension(int code)
            throws IOException {
        if (code < 1 || code > 3)
            throw new IOException("Invalid hold instruction code");
        holdInstructionCodeOID = holdInstructionCodeOIDs[code - 1];
        this.extensionId = PKIXExtensions.HoldInstructionCode_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create a HoldInstructionExtension with the date.
     * The criticality is set to false.
     *
     * @param oidStr the value to be set for the extension.
     */
    public HoldInstructionExtension(String oidStr)
            throws IOException {
        ObjectIdentifier oid = new ObjectIdentifier(oidStr);
        if (oid == null || getHoldInstructionCodeFromOID(oid) == 0)
            throw new IOException("Invalid hold instruction code");
        holdInstructionCodeOID = oid;
        this.extensionId = PKIXExtensions.HoldInstructionCode_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create a HoldInstructionExtension with the date.
     * The criticality is set to false.
     *
     * @param oid the value to be set for the extension.
     */
    public HoldInstructionExtension(ObjectIdentifier oid)
            throws IOException {
        if (getHoldInstructionCodeFromOID(oid) == 0)
            throw new IOException("Invalid hold instruction code");
        holdInstructionCodeOID = oid;
        this.extensionId = PKIXExtensions.HoldInstructionCode_Id;
        this.critical = false;
        encodeThis();
    }

    /**
     * Create a HoldInstructionExtension with the date.
     * The criticality is set to false.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param code the value to be set for the extension.
     */
    public HoldInstructionExtension(Boolean critical, int code)
            throws IOException {
        if (code < 1 || code > 3)
            throw new IOException("Invalid hold instruction code");
        holdInstructionCodeOID = holdInstructionCodeOIDs[code - 1];
        this.extensionId = PKIXExtensions.HoldInstructionCode_Id;
        this.critical = critical.booleanValue();
        encodeThis();
    }

    /**
     * Create a HoldInstructionExtension with the date.
     * The criticality is set to false.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param oidStr the value to be set for the extension.
     */
    public HoldInstructionExtension(Boolean critical, String oidStr)
            throws IOException {
        ObjectIdentifier oid = new ObjectIdentifier(oidStr);
        if (oid == null || getHoldInstructionCodeFromOID(oid) == 0)
            throw new IOException("Invalid hold instruction code");
        holdInstructionCodeOID = oid;
        this.extensionId = PKIXExtensions.HoldInstructionCode_Id;
        this.critical = critical.booleanValue();
        encodeThis();
    }

    /**
     * Create a HoldInstructionExtension with the date.
     * The criticality is set to false.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param oid the value to be set for the extension.
     */
    public HoldInstructionExtension(Boolean critical, ObjectIdentifier oid)
            throws IOException {
        if (getHoldInstructionCodeFromOID(oid) == 0)
            throw new IOException("Invalid hold instruction code");
        holdInstructionCodeOID = oid;
        this.extensionId = PKIXExtensions.HoldInstructionCode_Id;
        this.critical = critical.booleanValue();
        encodeThis();
    }

    /**
     * Create the extension from the passed DER encoded value of the same.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public HoldInstructionExtension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = PKIXExtensions.HoldInstructionCode_Id;
        this.critical = critical.booleanValue();

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        for (int i = 0; i < len; i++) {
            extValue[i] = Array.getByte(value, i);
        }
        this.extensionValue = extValue;
        DerValue val = new DerValue(extValue);
        if (val.tag == DerValue.tag_ObjectId) {
            DerInputStream derInputStream = new DerInputStream(val.toByteArray());
            holdInstructionCodeOID = derInputStream.getOID();
            if (getHoldInstructionCodeFromOID(holdInstructionCodeOID) == 0)
                throw new IOException("Invalid encoding for HoldInstructionExtension");
        } else {
            throw new IOException("Invalid encoding for HoldInstructionExtension");
        }
    }

    /**
     * Get the hold instruction code.
     */
    public ObjectIdentifier getHoldInstructionCode() {
        return holdInstructionCodeOID;
    }

    public String getHoldInstructionCodeDescription() {
        return getHoldInstructionDescription(holdInstructionCodeOID);
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        if (name.equalsIgnoreCase(HOLD_INSTRUCTION)) {
            if (!(obj instanceof ObjectIdentifier)) {
                throw new IOException("Attribute must be of type String.");
            }
            holdInstructionCodeOID = (ObjectIdentifier) obj;
        } else {
            throw new IOException("Attribute name not recognized by" +
                                  " CertAttrSet:HoldInstructionCode.");
        }
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        if (name.equalsIgnoreCase(HOLD_INSTRUCTION)) {
            return holdInstructionCodeOID;
        } else {
            throw new IOException("Attribute name not recognized by" +
                                  " CertAttrSet:HoldInstructionCode.");
        }
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        if (name.equalsIgnoreCase(HOLD_INSTRUCTION)) {
            holdInstructionCodeOID = null;
        } else {
            throw new IOException("Attribute name not recognized by" +
                                  " CertAttrSet:HoldInstructionCode.");
        }
    }

    /**
     * Returns a printable representation of the HoldInstructionExtension.
     */
    public String toString() {
        String s = super.toString() + "Hold Instruction Code: " +
                   getHoldInstructionDescription(holdInstructionCodeOID) + "\n";
        return (s);
    }

    /**
     * Decode the extension from the InputStream.
     *
     * @param in the InputStream to unmarshal the contents from.
     * @exception IOException on decoding or validity errors.
     */
    public void decode(InputStream in) throws IOException {
        throw new IOException("Method not to be called directly.");
    }

    /**
     * Write the extension to the DerOutputStream.
     *
     * @param out the DerOutputStream to write the extension to.
     * @exception IOException on encoding errors.
     */
    public void encode(OutputStream out) throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        if (this.extensionValue == null) {
            this.extensionId = PKIXExtensions.HoldInstructionCode_Id;
            this.critical = true;
            encodeThis();
        }
        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement(HOLD_INSTRUCTION);
        return (elements.elements());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return (NAME);
    }
}
