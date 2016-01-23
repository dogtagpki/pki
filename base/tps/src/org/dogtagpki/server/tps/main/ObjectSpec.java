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

        int val = objectSpec.getObjectIndex();

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
        id = objectSpec.getObjectIndex();

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

    public int getObjectIndex() {
        return ObjectSpec.getObjectIndex(this.objectID);
    }

    public static int getObjectIndex(long objectID) {
        char char_index = (char) ((objectID >> 16) & 0xff);
        int index = -1;

        if (char_index >= '0' && char_index <= '9') {
            index = char_index - '0';
        }
        if (char_index >= 'A' && char_index <= 'Z') {
            index = char_index - 'A' + 10;
        }
        if (char_index >= 'a' && char_index <= 'z') {
            index = char_index - 'a' + 26;
        }

        if ( index == -1) {
            index = 0x0100 + char_index;
        }

        return index;
    }

    public char getObjectType() {
        return ObjectSpec.getObjectType(objectID);
    }

    public static char getObjectType(long objectID) {
        char type = '0';
        type = (char) ((objectID >> 24) & 0xff);
        return type;
    }

    public static char getObjectIndexChar(long objectID) {
        char char_index = (char) ((objectID >> 16) & 0xff);
        return char_index;
    }

    public static long createObjectID(char type, int index) {
        long id = 0;

        if (type != 'c' && type != 'C' && type != 'k') {
            return 0;
        }

        if (index > 61 || index < 0) {
            return 0;
        }

        char indexChar = '0';

        long l1 = (type & 0xff) << 24;

        if (index >= 0 && index <= 9) {
            indexChar = (char) (index + '0');
        }

        // Handle 10 - 35 : A - Z

        if (index >= 10 && index <= 35) {
            indexChar = (char) (index - 10 + 'A');
        }

        // Handle 36 - 61 : a - z

        if (index >= 36 && index <= 61) {
            indexChar = (char) (index - 26 + 'a');
        }

        long l2 = (indexChar & 0xff) << 16;

        id = l1 + l2;

        return id;
    }

    public String getAttrId() {
        return ObjectSpec.getAttrId(this.objectID);
    }

    public static String getAttrId(long objectID) {
        String attrId = "";

        attrId = ObjectSpec.getObjectType(objectID) + String.valueOf(ObjectSpec.getObjectIndex(objectID));
        return attrId;
    }

    public static char getObjectType(String attrId) {

        long obj = ObjectSpec.createObjectID(attrId);
        return ObjectSpec.getObjectType(obj);
    }

    public static int getObjectIndex(String attrId) {
        long obj = ObjectSpec.createObjectID(attrId);
        return ObjectSpec.getObjectIndex(obj);
    }

    public static long createObjectID(String attrId) {
        long id = 0;

        if (attrId == null) {
            return 0;
        }

        // Allow ex: c0 - c9, or cA - cZ or  ca - cz
        // C or c or k allowed for types.

        int len = attrId.length();

        if (len < 2 || len > 3) {
            return 0;
        }

        String indexStr = attrId.substring(1);

        char typeCh = attrId.charAt(0);
        int index = 0;

        try
        {
            index = Integer.parseInt(indexStr.trim());
        } catch (NumberFormatException nfe)
        {
            CMS.debug("ObjectSpec.createObjectID(Str) bad object index string.");
            return 0;
        }

        id = ObjectSpec.createObjectID(typeCh, index);
        return id;
    }

    public static void main(String[] args) {
        String attr1 = "k0";
        String attr2 = "k10";
        String attr3 = "c27";
        String attr4 = "C37";

        long objectID1 = ObjectSpec.createObjectID(attr1);
        long objectID2 = ObjectSpec.createObjectID(attr2);
        long objectID3 = ObjectSpec.createObjectID(attr3);
        long objectID4 = ObjectSpec.createObjectID(attr4);

        System.out.println("objectID1: " + objectID1);
        System.out.println("objectID2: " + objectID2);
        System.out.println("objectID3: " + objectID3);
        System.out.println("objectID4: " + objectID4);

        System.out.println("\n");

        System.out.println("attr1 values: " + attr1 + "\n");

        char type1 = ObjectSpec.getObjectType(objectID1);
        System.out.println("type1: " + type1);

        int index1 = ObjectSpec.getObjectIndex(objectID1);
        System.out.println("index1: " + index1);

        System.out.println("index1 getAttrId: " + ObjectSpec.getAttrId(objectID1));

        System.out.println("\n");

        System.out.println("attr2 values: " + attr2 + "\n");

        char type2 = ObjectSpec.getObjectType(objectID2);
        System.out.println("type2: " + type2);

        int index2 = ObjectSpec.getObjectIndex(objectID2);
        System.out.println("index2: " + index2);
        System.out.println("index2 getAttrId: " + ObjectSpec.getAttrId(objectID2));
        System.out.println("\n");

        System.out.println("attr3 values: " + attr3 + "\n");

        char type3 = ObjectSpec.getObjectType(objectID3);
        System.out.println("type3: " + type3);

        int index3 = ObjectSpec.getObjectIndex(objectID3);
        System.out.println("index3: " + index3);
        System.out.println("index3 getAttrId: " + ObjectSpec.getAttrId(objectID3));
        System.out.println("\n");

        System.out.println("attr4 values: " + attr4 + "\n");

        char type4 = ObjectSpec.getObjectType(objectID4);
        System.out.println("type4: " + type4);

        int index4 = ObjectSpec.getObjectIndex(objectID4);
        System.out.println("index4: " + index4);
        System.out.println("index4 getAttrId: " + ObjectSpec.getAttrId(objectID4));
        System.out.println("\n");

        long test_id = 1798307840;

        char testType = ObjectSpec.getObjectType(test_id);
        int testIndex = ObjectSpec.getObjectIndex(test_id);

        System.out.println("test_id: " + test_id + " testType: " + testType + " testIndex: " + testIndex);
        System.out.println("\n");
    }

}
