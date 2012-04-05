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
package netscape.security.extensions;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.StringTokenizer;
import java.util.Vector;

import netscape.security.util.BigInt;
import netscape.security.util.DerOutputStream;
import netscape.security.util.DerValue;
import netscape.security.util.ObjectIdentifier;
import netscape.security.x509.CertAttrSet;
import netscape.security.x509.Extension;
import netscape.security.x509.OIDMap;

/**
 * Represent the AsnInteger Extension.
 */
public class GenericASN1Extension extends Extension
        implements CertAttrSet {
    /**
     *
     */
    private static final long serialVersionUID = 8047548816784949009L;

    protected static final int MAX_ATTR = 10;

    protected static final String PROP_CRITICAL =
              "critical";
    protected static final String PROP_NAME =
              "name";
    protected static final String PROP_OID =
              "oid";
    protected static final String PROP_PATTERN =
              "pattern";
    protected static final String PROP_ATTRIBUTE =
              "attribute";
    protected static final String PROP_TYPE =
              "type";
    protected static final String PROP_SOURCE =
              "source";
    protected static final String PROP_VALUE =
              "value";
    protected static final String PROP_PREDICATE =
              "predicate";
    /**
     * Identifier for this attribute, to be used with the
     * get, set, delete methods of Certificate, x509 type.
     */
    private String name;
    public String OID = null;
    public static Hashtable<String, String> mConfig = null;
    public String pattern = null;
    private int index = 0;

    // Encode this value
    private void encodeThis()
            throws IOException, ParseException {
        this.extensionValue = encodePattern();
    }

    // Encode pattern
    private byte[] encodePattern()
            throws IOException, ParseException {
        DerOutputStream os = new DerOutputStream();
        DerOutputStream tmp = new DerOutputStream();
        String type = null;
        String value = null;
        String source = null;
        while (index < pattern.length()) {
            char ch = pattern.charAt(index);
            switch (ch) {
            case '{':
                index++;
                byte[] buff = encodePattern();
                tmp.putDerValue(new DerValue(buff));
                break;
            case '}':
                os.write(DerValue.tag_Sequence, tmp);
                return os.toByteArray();
            default:
                type = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_TYPE);
                if (type.equalsIgnoreCase("integer")) {
                    int num = Integer.parseInt(mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_VALUE));
                    PutInteger(tmp, num);
                } else if (type.equalsIgnoreCase("ia5string")) {
                    source = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_SOURCE);
                    value = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_VALUE);
                    if (source.equalsIgnoreCase("file"))
                        PutIA5String(tmp, getFromFile(value));
                    else
                        PutIA5String(tmp, value);
                } else if (type.equalsIgnoreCase("octetstring")) {
                    source = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_SOURCE);
                    value = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_VALUE);
                    // It should be colon seperated ASCII Hexdecimal String
                    if (source.equalsIgnoreCase("file"))
                        PutOctetString(tmp, getFromFile(value));
                    else
                        PutOctetString(tmp, value);
                } else if (type.equalsIgnoreCase("bmpstring")) {
                    source = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_SOURCE);
                    value = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_VALUE);
                    if (source.equalsIgnoreCase("file"))
                        PutBMPString(tmp, getFromFile(value));
                    else
                        PutBMPString(tmp, value);
                } else if (type.equalsIgnoreCase("printablestring")) {
                    source = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_SOURCE);
                    value = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_VALUE);
                    if (source.equalsIgnoreCase("file"))
                        PutPrintableString(tmp, getFromFile(value));
                    else
                        PutPrintableString(tmp, value);
                } else if (type.equalsIgnoreCase("visiblestring")) {
                    source = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_SOURCE);
                    value = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_VALUE);
                    if (source.equalsIgnoreCase("file"))
                        PutVisibleString(tmp, getFromFile(value));
                    else
                        PutVisibleString(tmp, value);
                } else if (type.equalsIgnoreCase("utctime")) {
                    value = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_VALUE);
                    PutUTCtime(tmp, value);
                } else if (type.equalsIgnoreCase("oid")) {
                    value = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_VALUE);
                    PutOID(tmp, value);
                } else if (type.equalsIgnoreCase("boolean")) {
                    boolean bool = false;
                    String b = mConfig.get(PROP_ATTRIBUTE + "." + ch + "." + PROP_VALUE);
                    if (b.equalsIgnoreCase("true"))
                        bool = true;
                    else
                        bool = false;
                    PutBoolean(tmp, bool);
                } else if (type.equalsIgnoreCase("null")) {
                    tmp.putNull();
                } else {
                    throw new ParseException("Unknown Attribute Type", 0);
                }
            }
            index++;
        }

        return tmp.toByteArray();
    }

    /**
     * Create a GenericASN1Extension with the value and oid.
     * The criticality is set to false.
     *
     * @param the values to be set for the extension.
     */
    public GenericASN1Extension(String name, String oid, String pattern, boolean critical,
            Hashtable<String, String> config)
            throws IOException, ParseException {
        ObjectIdentifier tmpid = new ObjectIdentifier(oid);
        this.name = name;
        OID = oid;
        mConfig = config;
        this.pattern = pattern;

        try {
            if (OIDMap.getName(tmpid) == null)
                OIDMap.addAttribute("netscape.security.x509.GenericASN1Extension", oid, name);
        } catch (CertificateException e) {
        }

        this.extensionId = tmpid;
        this.critical = critical;
        encodeThis();
    }

    /**
     * Create a GenericASN1Extension with the value and oid.
     * The criticality is set to false.
     *
     * @param the values to be set for the extension.
     */
    public GenericASN1Extension(Hashtable<String, String> config)
            throws IOException, ParseException {
        mConfig = config;
        ObjectIdentifier tmpid = new ObjectIdentifier(mConfig.get(PROP_OID));
        name = mConfig.get(PROP_NAME);
        OID = mConfig.get(PROP_OID);
        pattern = mConfig.get(PROP_PATTERN);

        try {
            if (OIDMap.getName(tmpid) == null)
                OIDMap.addAttribute("GenericASN1Extension", OID, name);
        } catch (CertificateException e) {
        }

        this.extensionId = tmpid;
        this.critical = false;
        String b = mConfig.get(PROP_CRITICAL);
        if (b.equalsIgnoreCase("true"))
            this.critical = true;
        else
            this.critical = false;
        encodeThis();
    }

    /**
     * Create the extension from the passed DER encoded value of the same.
     *
     * @param critical true if the extension is to be treated as critical.
     * @param value Array of DER encoded bytes of the actual value.
     * @exception IOException on error.
     */
    public GenericASN1Extension(Boolean critical, Object value)
            throws IOException {
        this.extensionId = new ObjectIdentifier(OID);
        this.critical = critical.booleanValue();

        int len = Array.getLength(value);
        byte[] extValue = new byte[len];
        for (int i = 0; i < len; i++) {
            extValue[i] = Array.getByte(value, i);
        }
        this.extensionValue = extValue;
    }

    /**
     * Set the attribute value.
     */
    public void set(String name, Object obj) throws IOException {
        throw new IOException("Method not to be called directly.");
    }

    /**
     * Get the attribute value.
     */
    public Object get(String name) throws IOException {
        return null;
    }

    /**
     * Delete the attribute value.
     */
    public void delete(String name) throws IOException {
        throw new IOException("Method not to be called directly.");
    }

    /**
     * Returns a printable representation of the GenericASN1Extension.
     */
    public String toString() {
        return (null);
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
    public void encode(OutputStream out)
            throws IOException {
        DerOutputStream tmp = new DerOutputStream();

        try {
            if (this.extensionValue == null) {
                this.extensionId = new ObjectIdentifier(OID);
                this.critical = true;
                encodeThis();
            }
        } catch (ParseException e) {
        }

        super.encode(tmp);
        out.write(tmp.toByteArray());
    }

    /**
     * Return the name of this attribute.
     */
    public String getName() {
        return name;
    }

    /**
     * Set the name of this attribute.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Return the OID of this attribute.
     */
    public String getOID() {
        return OID;
    }

    /**
     * Set the OID of this attribute.
     */
    public void setOID(String oid) {
        OID = oid;
    }

    /**
     * Return an enumeration of names of attributes existing within this
     * attribute.
     */
    public Enumeration<String> getAttributeNames() {
        Vector<String> elements = new Vector<String>();
        elements.addElement("octet");

        return (elements.elements());
    }

    private void PutInteger(DerOutputStream os, int number)
            throws IOException, ParseException {
        os.putInteger(new BigInt(number));
        return;
    }

    private void PutIA5String(DerOutputStream os, String value)
            throws IOException, ParseException {
        os.putIA5String(value);
        return;
    }

    private void PutOctetString(DerOutputStream os, String value)
            throws IOException, ParseException {
        StringTokenizer token = new StringTokenizer(value, ":");
        byte[] octets = new byte[token.countTokens()];
        for (int i = 0; token.hasMoreElements(); i++) {
            String num = (String) token.nextElement();
            octets[i] = (byte) Integer.parseInt(num, 16);
        }

        os.putOctetString(octets);
        return;
    }

    private void PutBMPString(DerOutputStream os, String value)
            throws IOException, ParseException {
        os.putBMPString(value);
        return;
    }

    private void PutPrintableString(DerOutputStream os, String value)
            throws IOException, ParseException {
        os.putPrintableString(value);
        return;
    }

    private void PutVisibleString(DerOutputStream os, String value)
            throws IOException, ParseException {
        os.putVisibleString(value);
        return;
    }

    private void PutUTCtime(DerOutputStream os, String value)
            throws IOException, ParseException {
        DateFormat df = DateFormat.getDateInstance(DateFormat.SHORT);
        os.putUTCTime(df.parse(value));
        return;
    }

    private void PutOID(DerOutputStream os, String value)
            throws IOException, ParseException {
        os.putOID(new ObjectIdentifier(value));
        return;
    }

    private void PutBoolean(DerOutputStream os, boolean value)
            throws IOException, ParseException {
        os.putBoolean(value);
        return;
    }

    private String getFromFile(String fname) throws IOException {
        String s = null;
        byte[] buff = null;
        int i = 0;
        int j = 0;
        if ((fname == null) || (fname.equals(""))) {
            throw new IOException("File name is not provided.");
        }

        FileInputStream fis = new FileInputStream(fname);
        int n = 0;
        while ((n = fis.available()) > 0) {
            buff = new byte[n];
            int result = fis.read(buff);
            if (result == -1)
                break;
            s = new String(buff);
        }

        for (i = 0, j = 0; j < s.length(); j++) {
            int ch = s.charAt(j);
            if (ch == 10 || ch == 13 || ch == 9)
                continue;
            i++;
        }
        buff = new byte[i];
        for (i = 0, j = 0; j < s.length(); j++) {
            int ch = s.charAt(j);
            if (ch == 10 || ch == 13 || ch == 9)
                continue;
            buff[i++] = (byte) ch;
        }

        s = new String(buff);

        return s;
    }
}
