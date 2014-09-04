package org.dogtagpki.server.tps.main;

import java.util.ArrayList;

import org.dogtagpki.tps.main.TPSBuffer;
import org.dogtagpki.tps.main.TPSException;

import sun.security.pkcs11.wrapper.PKCS11Constants;

import com.netscape.certsrv.apps.CMS;

public class ObjectSpec {

    public ObjectSpec()
    {
        attributeSpecs = new ArrayList<AttributeSpec>();
    }

    final static int DATATYPE_STRING = 0;
    final static int DATATYPE_INTEGER = 1;
    final static int DATATYPE_BOOL_FALSE = 2;
    final static int DATATYPE_BOOL_TRUE = 3;

    private long objectID;
    private long fixedAttributes;
    private ArrayList<AttributeSpec> attributeSpecs;
    private int parseRead;

    public int getParseReadSize() {
        return parseRead;
    }

    /**
     * Parse 'c' object.
     */
    public static void parseAttributes(String objectID, ObjectSpec objectSpec, TPSBuffer b)
    {
        int curpos = 7;
        long fixedAttrs = 0;
        int xclass = 0;
        int id = 0;

        /* skip first 7 bytes */

        while (curpos < ((b.size()))) {
            long attribute_id = b.getLongFrom4Bytes(curpos);
            int attribute_size = b.getIntFrom2Bytes(curpos + 4);

            byte type = 0;
            TPSBuffer data = new TPSBuffer();
            boolean found = false;
            /* modify fixed attributes */

            switch ((int) attribute_id) {
            case (int) PKCS11Constants.CKA_TOKEN:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00000080;
                }
                break;
            case (int) PKCS11Constants.CKA_PRIVATE:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00000100;
                } else {
                }
                break;
            case (int) PKCS11Constants.CKA_MODIFIABLE:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00000200;
                }
                break;
            case (int) PKCS11Constants.CKA_DERIVE:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00000400;
                }
                break;
            case (int) PKCS11Constants.CKA_LOCAL:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00000800;
                }
                break;
            case (int) PKCS11Constants.CKA_ENCRYPT:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00001000;
                }
                break;
            case (int) PKCS11Constants.CKA_DECRYPT:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00002000;
                }
                break;
            case (int) PKCS11Constants.CKA_WRAP:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00004000;
                }
                break;
            case (int) PKCS11Constants.CKA_UNWRAP:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00008000;
                }
                break;
            case (int) PKCS11Constants.CKA_SIGN:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00010000;
                }
                break;
            case (int) PKCS11Constants.CKA_SIGN_RECOVER:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00020000;
                }
                break;
            case (int) PKCS11Constants.CKA_VERIFY:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00040000;
                }
                break;
            case (int) PKCS11Constants.CKA_VERIFY_RECOVER:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00080000;
                }
                break;
            case (int) PKCS11Constants.CKA_SENSITIVE:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00100000;
                }
                break;
            case (int) PKCS11Constants.CKA_ALWAYS_SENSITIVE:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00200000;
                }
                break;
            case (int) PKCS11Constants.CKA_EXTRACTABLE:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00400000;
                }
                break;
            case (int) PKCS11Constants.CKA_NEVER_EXTRACTABLE:
                if (b.at(curpos + 6) != 0) {
                    fixedAttrs |= 0x00800000;
                }
                break;
            case (int) PKCS11Constants.CKA_SUBJECT:
                type = DATATYPE_STRING;
                data = b.substr(curpos + 6, attribute_size);
                /* build by PKCS11 */
                break;
            case (int) PKCS11Constants.CKA_LABEL:
                type = DATATYPE_STRING;
                data = b.substr(curpos + 6, attribute_size);
                found = true;
                break;
            case (int) PKCS11Constants.CKA_MODULUS:
                type = DATATYPE_STRING;
                data = b.substr(curpos + 6, attribute_size);
                /* build by PKCS11 */
                break;
            case (int) PKCS11Constants.CKA_ID:
                type = DATATYPE_STRING;
                data = b.substr(curpos + 6, attribute_size);
                /* build by PKCS11 */
                break;
            case (int) PKCS11Constants.CKA_KEY_TYPE:
                type = DATATYPE_INTEGER;
                data = b.substr(curpos + 6, 4);
                found = true;
                /* build by PKCS11 */
                break;
            case (int) PKCS11Constants.CKA_CLASS:
                type = DATATYPE_INTEGER;
                data = b.substr(curpos + 6, 4);
                xclass = data.at(0);
                /* build by PKCS11 */
                break;
            case (int) PKCS11Constants.CKA_PUBLIC_EXPONENT:
                type = DATATYPE_STRING;
                data = b.substr(curpos + 6, attribute_size);
                /* build by PKCS11 */
                break;
            case (int) PKCS11Constants.CKA_CERTIFICATE_TYPE:
                type = DATATYPE_INTEGER;
                data = b.substr(curpos + 6, 4);
                /* build by PKCS11 */
                break;

            case (int) PKCS11Constants.CKA_EC_PARAMS:
                type = DATATYPE_STRING;
                data = b.substr(curpos + 6, attribute_size);
                found = true;
                break;

            case (int) PKCS11Constants.CKA_EC_POINT:
                type = DATATYPE_STRING;
                data = b.substr(curpos + 6, attribute_size);
                found = true;
                break;
            default:
                CMS.debug("ObjectSpec.parseKeyBlob" +
                        "skipped attribute_id = " +
                        attribute_id);
                break;
            }

            if (found) {
                /* add attribute spec */
                AttributeSpec attrSpec = new AttributeSpec();
                attrSpec.setAttributeID(attribute_id);
                attrSpec.setType(type);

                switch (type) {
                case DATATYPE_STRING:
                    attrSpec.setData(data);
                    break;
                case DATATYPE_INTEGER:
                    attrSpec.setData(data);
                    break;
                case DATATYPE_BOOL_FALSE:
                    break;
                case DATATYPE_BOOL_TRUE:
                    break;
                default:
                    break;
                }

                objectSpec.addAttributeSpec(attrSpec);
            }

            curpos += 4 + 2 + attribute_size;
        }

        //Here the objectID fixed attribute gets massaged. Here's how:
        // The objectID becomes the cert container id, ex: 01
        // Each key pair associated with the cert must have the same ID.
        // This is done by math using the following formula:
        // Given a cert id of "2", the keyAttrIds of the keys are originally
        // configured as k4 and k5. Note that one is twice the cert id, and
        // the other is twice the cert id plus 1. In order to map the key ids
        // down to the cert's id, the code below changes both "4" and "5" back
        // to "2".

        int val = (objectID.charAt(1) - '0');
        switch (objectID.charAt(0)) {
        case 'c':

            id = val;

            break;
        case 'k':
            if ((val % 2) != 0) {
                id = (val - 1) / 2;
            } else {
                id = (val / 2);

            }

            break;
        }

        objectSpec.setFixedAttributes(fixedAttrs | (xclass << 4) | id);
    }

    /**
     * Parse 'c' object.
     */
    public static void parseCertificateAttributes(String objectID, ObjectSpec objectSpec, TPSBuffer b)
    {
        parseAttributes(objectID, objectSpec, b);
    }

    /**
     * Parse 'k' object.
     */
    public static void parseKeyAttributes(String objectID, ObjectSpec objectSpec, TPSBuffer b)
    {
        parseAttributes(objectID, objectSpec, b);
    }

    /**
     * Parse 'C' object.
     */
    public static void parseCertificateBlob(String objectID, ObjectSpec objectSpec, TPSBuffer b)
    {
        long fixedAttrs = 0;
        int xclass = 0;
        int id = 0;

        AttributeSpec value = new AttributeSpec();
        value.setAttributeID((int) PKCS11Constants.CKA_VALUE);
        value.setType((byte) DATATYPE_STRING);
        value.setData(b);
        objectSpec.addAttributeSpec(value);

        fixedAttrs = 0x00000080; /* CKA_TOKEN */
        xclass = (int) PKCS11Constants.CKO_CERTIFICATE;
        id = objectID.charAt(1) - '0';

        objectSpec.setFixedAttributes(fixedAttrs | (xclass << 4) | id);
    }

    /**
     * Convert object from token into object spec.
     *
     * Reference:
     * http://netkey/design/applet_readable_object_spec-0.1.txt
     * http://netkey/design/pkcs11obj.txt
     *
     * @throws TPSException
     */
    public static ObjectSpec parseFromTokenData(long objid, TPSBuffer b) throws TPSException
    {
        String objectID = null;

        StringBuilder idBuilder = new StringBuilder();

        ObjectSpec o = new ObjectSpec();
        o.setObjectID(objid);

        char[] b1 = new char[4];
        b1[0] = (char) ((objid >> 24) & 0xff);
        b1[1] = (char) ((objid >> 16) & 0xff);
        b1[2] = (char) ((objid >> 8) & 0xff);
        b1[3] = (char) (objid & 0xff);

        idBuilder.append(b1[0]);
        idBuilder.append(b1[1]);
        idBuilder.append(b1[2]);
        idBuilder.append(b1[3]);

        objectID = idBuilder.toString();
        switch (b1[0]) {
        case 'c': /* certificate attributes */
            parseCertificateAttributes(objectID, o, b);
            break;
        case 'k': /* public key or private key attributes */
            parseKeyAttributes(objectID, o, b);
            break;
        case 'C': /* certificate in DER */
            parseCertificateBlob(objectID, o, b);
            break;
        default:
            CMS.debug("ObjectSpec::ParseKeyBlob" +
                    "unknown objectID = " + objectID.charAt(0));
            throw new TPSException("ObjectSpec parseFromToken data: Invalid object type, aborting..");
        }

        return o;
    }

    public static ObjectSpec parse(TPSBuffer b, int offset) throws TPSException
    {
        int sum = 0;

        if ((b.size() - offset) < 10)
            return null;

        ObjectSpec o = new ObjectSpec();
        long id = b.getLongFrom4Bytes(offset);

        o.setObjectID(id);
        long attribute = b.getLongFrom4Bytes(offset + 4);

        o.setFixedAttributes(attribute);
        int count = b.getIntFrom2Bytes(offset + 8);
        sum += 10;
        int curpos = offset + 10;
        for (int i = 0; i < count; i++) {
            int len = 0;
            switch (b.at(curpos + 4)) {
            case DATATYPE_STRING:
                len = 4 + 1 + 2 + b.getIntFrom2Bytes(curpos + 5);
                break;
            case DATATYPE_INTEGER:
                len = 4 + 1 + 4;
                break;
            case DATATYPE_BOOL_FALSE:
                len = 4 + 1;
                break;
            case DATATYPE_BOOL_TRUE:
                len = 4 + 1;
                break;
            default:
                CMS.debug("ObjectSpec::parse" +
                        "unknown DataType = " + b.at(curpos + 4));
                throw new TPSException("ObjectSpec parse: Invalid data type, aborting..");
            }
            TPSBuffer attr = b.substr(curpos, len);
            AttributeSpec attrSpec = AttributeSpec.parse(attr, 0);
            o.addAttributeSpec(attrSpec);
            curpos += len;
            sum += len;
        }
        o.setParseRead(sum);
        return o;
    }

    private void setParseRead(int nread) {
        parseRead = nread;
    }

    void setObjectID(long v)
    {
        objectID = v;
    }

    public long getObjectID()
    {
        return objectID;
    }

    public void setFixedAttributes(long v)
    {
        fixedAttributes = v;
    }

    public long getFixedAttributes()
    {
        return fixedAttributes;
    }

    public int getAttributeSpecCount()
    {
        return attributeSpecs.size();
    }

    public AttributeSpec getAttributeSpec(int p)
    {
        return attributeSpecs.get(p);
    }

    public void addAttributeSpec(AttributeSpec p)
    {
        attributeSpecs.add(p);
    }

    public void removeAttributeSpec(int p)
    {
        attributeSpecs.remove(p);

    }

    TPSBuffer getData()
    {
        TPSBuffer data = new TPSBuffer();

        data.addLong4Bytes(objectID);
        data.addLong4Bytes(fixedAttributes);

        int attributeCount = getAttributeSpecCount();
        data.addInt2Bytes(attributeCount);
        for (int i = 0; i < attributeCount; i++) {
            AttributeSpec spec = getAttributeSpec(i);
            data.add(spec.getData());
        }

        return data;
    }

}
