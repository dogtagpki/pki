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
package com.netscape.cmscore.request;

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBDynAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.request.IRequestRecord;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

/**
 * Maps dynamic data for the extData- prefix to and from the extData Hashtable
 * in RequestRecord.
 *
 * The data in RequestRecord is stored in a Hashtable. It comes in two forms:
 * 1. String key1 => String value1
 * String key2 => String value2
 * This is stored in LDAP as:
 * extData-key1 => value1
 * extData-key2 => value2
 *
 * 2. String key => Hashtable value
 * where value stores:
 * String key2 => String value2
 * String key3 => String value3
 * This is stored in LDAP as:
 * extData-key;key2 => value2
 * extData-key;key3 => value3
 *
 * These can be mixed, but each top-level key can only be associated with
 * a String value or a Hashtable value.
 */
public class ExtAttrDynMapper implements IDBDynAttrMapper {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(ExtAttrDynMapper.class);

    protected final static String extAttrPrefix = "extdata-";

    protected final static Vector<String> mAttrs = new Vector<String>();

    static {
        mAttrs.add(Schema.LDAP_ATTR_EXT_ATTR);
    }

    public boolean supportsLDAPAttributeName(String attrName) {
        return (attrName != null) &&
                attrName.toLowerCase().startsWith(extAttrPrefix);
    }

    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return mAttrs.elements();
    }

    /**
     * Decodes extdata encoded keys.
     * -- followed by a 4 digit hexadecimal string is decoded to the character
     * representing the hex string.
     *
     * The routine is written to be highly efficient. It only allocates
     * the StringBuffer if needed and copies the pieces in large chunks.
     *
     * @param key The key to decode
     * @return The decoded key.
     */
    public String decodeKey(String key) {

        StringBuffer output = null;
        char[] input = key.toCharArray();
        int startCopyIndex = 0;

        int index = 0;
        while (index < input.length) {

            if (input[index] != '-') {
                index++;
                continue;
            }

            if (index + 1 >= input.length || input[index + 1] != '-') {
                index++;
                continue;
            }

            if (output == null) {
                output = new StringBuffer(input.length);
            }

            output.append(input, startCopyIndex, index - startCopyIndex);
            index += 2;

            if (index + 3 < input.length) {
                String value = new String(input, index, 4);
                int codePoint = Integer.parseInt(value, 16);
                char[] chars = Character.toChars(codePoint);
                output.append(chars);
            }

            index += 4;
            startCopyIndex = index;
        }

        if (output == null) {
            return key;
        }

        output.append(input, startCopyIndex, index - startCopyIndex);
        return output.toString();
    }

    /**
     * Encoded extdata keys for storage in LDAP.
     *
     * The rules for encoding are trickier than decoding. We want to allow
     * '-' by itself to be stored in the database (for the common case of keys
     * like 'Foo-Bar'. Therefore we are using '--' as the encoding character.
     * The rules are:
     * 1) All characters [^-a-zA-Z0-9] are encoded as --XXXX where XXXX is the
     * hex representation of the digit.
     * 2) [a-zA-Z0-9] are always passed through unencoded
     * 3) [-] is passed through as long as it is preceded and followed
     * by [a-zA-Z0-9] (or if it's at the beginning/end of the string)
     * 4) If [-] is preceded or followed by [^a-zA-Z0-9] then
     * the - as well as all following [^a-zA-Z0-9] characters are encoded
     * as --XXXX.
     *
     * This routine tries to be as efficient as possible with StringBuffer and
     * large copies. However, the encoding unfortunately requires several
     * objects to be allocated.
     *
     * @param key The key to encode
     * @return The encoded key
     */
    public String encodeKey(String key) {

        StringBuffer output = null;
        char[] input = key.toCharArray();
        int startCopyIndex = 0;

        int index = 0;
        while (index < input.length) {

            if (isAlphaNum(input[index])) {
                index++;
                continue;
            }

            if (input[index] == '-' &&
                    index + 1 < input.length &&
                    isAlphaNum(input[index + 1])) {
                index += 2;
                continue;
            }

            if (input[index] == '-' && index + 1 == input.length) {
                index += 1;
                continue;
            }

            if (output == null) {
                output = new StringBuffer(input.length + 5);
            }

            output.append(input, startCopyIndex, index - startCopyIndex);
            while (index < input.length && !isAlphaNum(input[index])) {
                output.append("--");
                String hexString = Integer.toHexString(input[index]);
                int padding = 4 - hexString.length();

                while (padding > 0) {
                    output.append('0');
                    padding--;
                }

                output.append(hexString);
                index++;
            }

            startCopyIndex = index;
        }

        if (output == null) {
            return key;
        }

        output.append(input, startCopyIndex, index - startCopyIndex);
        return output.toString();
    }

    protected boolean isAlphaNum(char in) {
        if (in >= 'a' && in <= 'z') {
            return true;
        }
        if (in >= 'A' && in <= 'Z') {
            return true;
        }
        if (in >= '0' && in <= '9') {
            return true;
        }
        return false;
    }

    public void mapObjectToLDAPAttributeSet(
            IDBObj parent,
            String name,
            Object obj,
            LDAPAttributeSet attrs)
            throws EBaseException {

        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }

        @SuppressWarnings("unchecked")
        Hashtable<String, Object> ht = (Hashtable<String, Object>) obj;

        Enumeration<String> e = ht.keys();
        while (e.hasMoreElements()) {
            String key = e.nextElement();
            Object value = ht.get(key);

            if (value instanceof String) {
                String stringValue = ((String) value).trim();
                if ("".equals(stringValue)) continue;

                String attrName = extAttrPrefix + encodeKey(key);
                logger.debug("ExtAttrDynMapper: adding " + attrName);
                attrs.add(new LDAPAttribute(attrName, stringValue));

            } else if (value instanceof Hashtable) {
                @SuppressWarnings("unchecked")
                Hashtable<String, String> innerHash = (Hashtable<String, String>) value;
                Enumeration<String> innerHashEnum = innerHash.keys();

                while (innerHashEnum.hasMoreElements()) {
                    String innerKey = innerHashEnum.nextElement();
                    String innerValue = innerHash.get(innerKey).trim();
                    if ("".equals(innerValue)) continue;

                    String attrName = extAttrPrefix + encodeKey(key) + ";" + encodeKey(innerKey);
                    logger.debug("ExtAttrDynMapper: adding " + attrName);
                    attrs.add(new LDAPAttribute(attrName, innerValue));
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    public void mapLDAPAttributeSetToObject(
            LDAPAttributeSet attrs,
            String name,
            IDBObj parent)
            throws EBaseException {

        Hashtable<String, Object> ht = new Hashtable<String, Object>();
        Hashtable<String, String> valueHashtable;

        Enumeration<LDAPAttribute> attrEnum = attrs.getAttributes();
        while (attrEnum.hasMoreElements()) {
            LDAPAttribute attr = attrEnum.nextElement();
            String baseName = attr.getBaseName();

            if (!baseName.toLowerCase().startsWith(extAttrPrefix)) {
                continue;
            }

            String keyName = decodeKey(baseName.substring(extAttrPrefix.length()));
            String[] subTypes = attr.getSubtypes();
            String[] values = attr.getStringValueArray();

            if (values.length != 1) {
                RequestId requestID = ((IRequestRecord) parent).getRequestId();
                String message = "Output Mapping Error in request ID " +
                        requestID + " : " +
                        "more than one value returned for " +
                        keyName;
                logger.error(message);
                throw new EBaseException(message);
            }

            if (subTypes == null || subTypes.length <= 0) {
                ht.put(keyName, values[0]);
                continue;
            }

            if (subTypes.length != 1) {
                RequestId requestID = ((IRequestRecord) parent).getRequestId();
                String message = "Output Mapping Error in request ID " +
                        requestID + " : " +
                        "more than one subType returned for " +
                        keyName;
                logger.error(message);
                throw new EBaseException(message);
            }

            Object value = ht.get(keyName);
            if (value != null && !(value instanceof Hashtable)) {
                RequestId requestID = ((IRequestRecord) parent).getRequestId();
                String message = "Output Mapping Error in request ID " +
                        requestID + " : " +
                        "combined no-subtype and subtype data for key " +
                        keyName;
                logger.error(message);
                throw new EBaseException(message);
            }

            valueHashtable = (Hashtable<String, String>) value;
            if (valueHashtable == null) {
                valueHashtable = new Hashtable<String, String>();
                ht.put(keyName, valueHashtable);
            }

            valueHashtable.put(decodeKey(subTypes[0]), values[0]);
        }

        parent.set(name, ht);
    }

    public String mapSearchFilter(String name, String op, String value) throws EBaseException {
        return name + op + value;
    }
}
