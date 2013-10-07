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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.math.BigInteger;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

import com.netscape.certsrv.apps.CMS;
import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.EDBException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBDynAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.dbs.IDBRegistry;
import com.netscape.certsrv.dbs.IDBSubsystem;
import com.netscape.certsrv.dbs.Modification;
import com.netscape.certsrv.dbs.ModificationSet;
import com.netscape.certsrv.request.IRequest;
import com.netscape.certsrv.request.IRequestRecord;
import com.netscape.certsrv.request.RequestId;
import com.netscape.certsrv.request.RequestStatus;
import com.netscape.certsrv.request.ldap.IRequestMod;
import com.netscape.cmscore.dbs.BigIntegerMapper;
import com.netscape.cmscore.dbs.DateMapper;
import com.netscape.cmscore.dbs.StringMapper;
import com.netscape.cmscore.util.Debug;

//
// A request record is the stored version of a request.
// It has a set of attributes that are mapped into LDAP
// attributes for actual directory operations.
//
public class RequestRecord
        extends ARequestRecord
        implements IRequestRecord, IDBObj {
    /**
     *
     */
    private static final long serialVersionUID = 8044665107558872084L;

    public RequestId getRequestId() {
        return mRequestId;
    }

    public Enumeration<String> getAttrNames() {
        return mAttrTable.keys();
    }

    // IDBObj.get
    public Object get(String name) {
        if (name.equals(IRequestRecord.ATTR_REQUEST_ID))
            return mRequestId;
        else if (name.equals(IRequestRecord.ATTR_REQUEST_STATE))
            return mRequestState;
        else if (name.equals(IRequestRecord.ATTR_REQUEST_TYPE))
            return mRequestType;
        else if (name.equals(IRequestRecord.ATTR_MODIFY_TIME))
            return mModifyTime;
        else if (name.equals(IRequestRecord.ATTR_CREATE_TIME))
            return mCreateTime;
        else if (name.equals(IRequestRecord.ATTR_SOURCE_ID))
            return mSourceId;
        else if (name.equals(IRequestRecord.ATTR_REQUEST_OWNER))
            return mOwner;
        else if (name.equals(IRequestRecord.ATTR_EXT_DATA))
            return mExtData;
        else {
            RequestAttr ra = mAttrTable.get(name);

            if (ra != null)
                return ra.get(this);
        }

        return null;
    }

    // IDBObj.set
    @SuppressWarnings("unchecked")
    public void set(String name, Object o) {
        if (name.equals(IRequestRecord.ATTR_REQUEST_ID))
            mRequestId = (RequestId) o;
        else if (name.equals(IRequestRecord.ATTR_REQUEST_STATE))
            mRequestState = (RequestStatus) o;
        else if (name.equals(IRequestRecord.ATTR_REQUEST_TYPE))
            mRequestType = (String) o;
        else if (name.equals(IRequestRecord.ATTR_CREATE_TIME))
            mCreateTime = (Date) o;
        else if (name.equals(IRequestRecord.ATTR_MODIFY_TIME))
            mModifyTime = (Date) o;
        else if (name.equals(IRequestRecord.ATTR_SOURCE_ID))
            mSourceId = (String) o;
        else if (name.equals(IRequestRecord.ATTR_REQUEST_OWNER))
            mOwner = (String) o;
        else if (name.equals(IRequestRecord.ATTR_EXT_DATA))
            mExtData = (Hashtable<String, Object>) o;
        else {
            RequestAttr ra = mAttrTable.get(name);

            if (ra != null)
                ra.set(this, o);
        }
    }

    // IDBObj.delete
    public void delete(String name)
            throws EBaseException {
        throw new EBaseException("Invalid call to delete");
    }

    // IDBObj.getElements
    public Enumeration<String> getElements() {
        return mAttrs.elements();
    }

    // IDBObj.getSerializableAttrNames
    public Enumeration<String> getSerializableAttrNames() {
        return mAttrs.elements();
    }

    // copy values from r to the local record
    void add(IRequest r) throws EBaseException {
        // Collect the values for the record
        mRequestId = r.getRequestId();
        mRequestType = r.getRequestType();
        mRequestState = r.getRequestStatus();
        mSourceId = r.getSourceId();
        mOwner = r.getRequestOwner();
        mCreateTime = r.getCreationTime();
        mModifyTime = r.getModificationTime();
        mExtData = loadExtDataFromRequest(r);

        for (int i = 0; i < mRequestA.length; i++) {
            mRequestA[i].add(r, this);
        }
    }

    void read(IRequestMod a, IRequest r) throws EBaseException {
        a.modRequestStatus(r, mRequestState);
        r.setSourceId(mSourceId);
        r.setRequestOwner(mOwner);
        a.modModificationTime(r, mModifyTime);
        a.modCreationTime(r, mCreateTime);
        storeExtDataIntoRequest(r);

        for (int i = 0; i < mRequestA.length; i++) {
            mRequestA[i].read(a, r, this);
        }
    }

    static void mod(ModificationSet mods, IRequest r) throws EBaseException {
        //
        mods.add(IRequestRecord.ATTR_REQUEST_STATE,
                Modification.MOD_REPLACE, r.getRequestStatus());

        mods.add(IRequestRecord.ATTR_SOURCE_ID,
                Modification.MOD_REPLACE, r.getSourceId());

        mods.add(IRequestRecord.ATTR_REQUEST_OWNER,
                Modification.MOD_REPLACE, r.getRequestOwner());

        mods.add(IRequestRecord.ATTR_MODIFY_TIME,
                Modification.MOD_REPLACE, r.getModificationTime());

        mods.add(IRequestRecord.ATTR_EXT_DATA,
                Modification.MOD_REPLACE, loadExtDataFromRequest(r));

        for (int i = 0; i < mRequestA.length; i++) {
            mRequestA[i].mod(mods, r);
        }
    }

    static void register(IDBSubsystem db)
            throws EDBException {
        IDBRegistry reg = db.getRegistry();

        reg.registerObjectClass(RequestRecord.class.getName(), mOC);

        reg.registerAttribute(IRequestRecord.ATTR_REQUEST_ID, new RequestIdMapper());
        reg.registerAttribute(IRequestRecord.ATTR_REQUEST_STATE, new RequestStateMapper());
        reg.registerAttribute(IRequestRecord.ATTR_CREATE_TIME,
                new DateMapper(Schema.LDAP_ATTR_CREATE_TIME));
        reg.registerAttribute(IRequestRecord.ATTR_MODIFY_TIME,
                new DateMapper(Schema.LDAP_ATTR_MODIFY_TIME));
        reg.registerAttribute(IRequestRecord.ATTR_SOURCE_ID,
                new StringMapper(Schema.LDAP_ATTR_SOURCE_ID));
        reg.registerAttribute(IRequestRecord.ATTR_REQUEST_OWNER,
                new StringMapper(Schema.LDAP_ATTR_REQUEST_OWNER));
        ExtAttrDynMapper extAttrMapper = new ExtAttrDynMapper();
        reg.registerAttribute(IRequestRecord.ATTR_EXT_DATA, extAttrMapper);
        reg.registerDynamicMapper(extAttrMapper);

        for (int i = 0; i < mRequestA.length; i++) {
            RequestAttr ra = mRequestA[i];

            reg.registerAttribute(ra.mAttrName, ra.mMapper);
        }
    }

    protected static final String mOC[] =
        { Schema.LDAP_OC_TOP, Schema.LDAP_OC_REQUEST, Schema.LDAP_OC_EXTENSIBLE };

    protected static Hashtable<String, Object> loadExtDataFromRequest(IRequest r) throws EBaseException {
        Hashtable<String, Object> h = new Hashtable<String, Object>();

        Enumeration<String> e = r.getExtDataKeys();
        while (e.hasMoreElements()) {
            String key = e.nextElement();
            if (r.isSimpleExtDataValue(key)) {
                h.put(key, r.getExtDataInString(key));
            } else {
                h.put(key, r.getExtDataInHashtable(key));
            }
        }

        return h;
    }

    @SuppressWarnings("unchecked")
    protected void storeExtDataIntoRequest(IRequest r) throws EBaseException {
        Enumeration<String> e = mExtData.keys();
        while (e.hasMoreElements()) {
            String key = e.nextElement();
            Object value = mExtData.get(key);
            if (value instanceof String) {
                r.setExtData(key, (String) value);
            } else if (value instanceof Hashtable) {
                r.setExtData(key, (Hashtable<String, String>) value);
            } else {
                throw new EDBException("Illegal data value in RequestRecord: " +
                        r.toString());
            }
        }
    }

    protected static Vector<String> mAttrs = new Vector<String>();

    static Hashtable<String, RequestAttr> mAttrTable = new Hashtable<String, RequestAttr>();

    /*
     * This table contains attribute handlers for attributes
     * of the request.  These attributes are ones that are stored
     * apart from the generic name/value pairs supported by the get/set
     * interface plus the hashtable for the name/value pairs themselves.
     *
     * NOTE: Eventually, all attributes should be done here.  Currently
     *   only the last ones added are implemented this way.
     */
    static RequestAttr mRequestA[] = {

    new RequestAttr(IRequest.ATTR_REQUEST_TYPE,
                new StringMapper(Schema.LDAP_ATTR_REQUEST_TYPE)) {
        void set(ARequestRecord r, Object o) {
            r.mRequestType = (String) o;
        }

        Object get(ARequestRecord r) {
            return r.mRequestType;
        }

        void read(IRequestMod a, IRequest r, ARequestRecord rr) {
            r.setRequestType(rr.mRequestType);
        }

        void add(IRequest r, ARequestRecord rr) {
            rr.mRequestType = r.getRequestType();
        }

        void mod(ModificationSet mods, IRequest r) {
            addmod(mods, r.getRequestType());
        }
    }

    };
    static {
        mAttrs.add(IRequestRecord.ATTR_REQUEST_ID);
        mAttrs.add(IRequestRecord.ATTR_REQUEST_STATE);
        mAttrs.add(IRequestRecord.ATTR_CREATE_TIME);
        mAttrs.add(IRequestRecord.ATTR_MODIFY_TIME);
        mAttrs.add(IRequestRecord.ATTR_SOURCE_ID);
        mAttrs.add(IRequestRecord.ATTR_REQUEST_OWNER);
        mAttrs.add(IRequestRecord.ATTR_EXT_DATA);

        for (int i = 0; i < mRequestA.length; i++) {
            RequestAttr ra = mRequestA[i];

            mAttrs.add(ra.mAttrName);
            mAttrTable.put(ra.mAttrName, ra);
        }
    }

}

//
// A mapper between an request state object and
// its LDAP attribute representation
// <P>
//
// @author thayes
// @version $Revision$ $Date$
//
class RequestStateMapper
        implements IDBAttrMapper {
    // IDBAttrMapper methods

    //
    //
    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return mAttrs.elements();
    }

    //
    public void mapObjectToLDAPAttributeSet(IDBObj parent,
            String name, Object obj, LDAPAttributeSet attrs) throws EBaseException {
        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }
        RequestStatus rs = (RequestStatus) obj;

        attrs.add(new LDAPAttribute(Schema.LDAP_ATTR_REQUEST_STATE,
                rs.toString()));
    }

    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent)
            throws EBaseException {
        LDAPAttribute attr = attrs.getAttribute(Schema.LDAP_ATTR_REQUEST_STATE);

        if (attr == null)
            throw new EBaseException("schema violation");

        String value = (String) attr.getStringValues().nextElement();

        parent.set(name, RequestStatus.fromString(value));
    }

    public String mapSearchFilter(String name, String op, String value) {
        return Schema.LDAP_ATTR_REQUEST_STATE + op + value;
    }

    protected final static Vector<String> mAttrs = new Vector<String>();

    static {
        mAttrs.add(Schema.LDAP_ATTR_REQUEST_STATE);
    }
}

//
// A mapper between an request id object and
// its LDAP attribute representation
// <P>
//
// @author thayes
// @version $Revision$ $Date$
//
class RequestIdMapper
        implements IDBAttrMapper {
    // IDBAttrMapper methods

    //
    //
    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return mAttrs.elements();
    }

    //
    public void mapObjectToLDAPAttributeSet(IDBObj parent,
            String name, Object obj, LDAPAttributeSet attrs) throws EBaseException {
        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }
        RequestId rid = (RequestId) obj;

        String v = BigIntegerMapper.BigIntegerToDB(new BigInteger(rid.toString()));

        attrs.add(new LDAPAttribute(Schema.LDAP_ATTR_REQUEST_ID, v));
    }

    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent)
            throws EBaseException {
        LDAPAttribute attr = attrs.getAttribute(Schema.LDAP_ATTR_REQUEST_ID);

        if (attr == null)
            throw new EBaseException("schema violation");

        String value = (String) attr.getStringValues().nextElement();

        parent.set(name, new RequestId(
                BigIntegerMapper.BigIntegerFromDB(value).toString()));
    }

    public String mapSearchFilter(String name, String op, String value) throws EBaseException {
        String v = null;

        try {
            v = BigIntegerMapper.BigIntegerToDB(new BigInteger(value));
        } catch (NumberFormatException e) {
            v = value;
        }
        return Schema.LDAP_ATTR_REQUEST_ID + op + v;
    }

    protected final static Vector<String> mAttrs = new Vector<String>();

    static {
        mAttrs.add(Schema.LDAP_ATTR_REQUEST_ID);
    }
}

/**
 * A mapper between an request attr set and its LDAP attribute representation.
 *
 * The attr attribute is no longer used. This class is kept for historical
 * and migration purposes.
 *
 * @author thayes
 * @version $Revision$ $Date$
 * @deprecated
 */
class RequestAttrsMapper
        implements IDBAttrMapper {
    // IDBAttrMapper methods

    //
    //
    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return mAttrs.elements();
    }

    //
    public void mapObjectToLDAPAttributeSet(IDBObj parent,
            String name, Object obj, LDAPAttributeSet attrs) throws EBaseException {
        if (obj == null) {
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        }
        @SuppressWarnings("unchecked")
        Hashtable<String, Object> ht = (Hashtable<String, Object>) obj;
        Enumeration<String> e = ht.keys();
        ByteArrayOutputStream bos = null;
        ObjectOutputStream os = null;
        try {
            bos = new ByteArrayOutputStream();
            os = new ObjectOutputStream(bos);

            String key = null;
            Object value = null;

            while (e.hasMoreElements()) {
                key = e.nextElement();
                value = ht.get(key);
                byte data[] = null;

                try {
                    data = encode(value);
                    os.writeObject(key);
                    os.writeObject(data);
                } catch (NotSerializableException x) {
                    if (Debug.ON) {
                        System.err.println("Error: attribute '" + key + "' (" +
                                x.getMessage() + ") is not serializable");
                        x.printStackTrace();
                    }
                } catch (Exception x) {
                    if (Debug.ON) {
                        System.err.println("Error: attribute '" + key +
                                "' - error during serialization: " + x);
                        x.printStackTrace();
                    }
                }
            }

            os.writeObject(null);

        } catch (Exception x) {
            if (parent != null)
                Debug.trace("Output Mapping Error in requeset ID " +
                        ((RequestRecord) parent).getRequestId().toString() + " : " + x);
            //if (Debug.ON) {
            Debug.printStackTrace(x);
            //}
            throw new EBaseException(CMS.getUserMessage("CMS_DBS_SERIALIZE_FAILED", name));
        } finally {
            if (os != null) {
                try {
                    os.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
            if (bos != null) {
                try {
                    bos.close();
                } catch (IOException e1) {
                    e1.printStackTrace();
                }
            }
        }
        attrs.add(new LDAPAttribute(Schema.LDAP_ATTR_REQUEST_ATTRS,
                bos.toByteArray()));
    }

    private byte[] encode(Object value)
            throws NotSerializableException, IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(bos);

        os.writeObject(value);
        os.close();

        return bos.toByteArray();
    }

    private Object decode(byte[] data)
            throws ObjectStreamException, IOException, ClassNotFoundException {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(bis);

        return is.readObject();
    }

    private Hashtable<String, Object> decodeHashtable(byte[] data)
            throws ObjectStreamException, IOException, ClassNotFoundException {
        Hashtable<String, Object> ht = new Hashtable<String, Object>();
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(bis);

        String key = null;

        try {

            while (true) {
                key = (String) is.readObject();

                // end of table is marked with null
                if (key == null)
                    break;

                byte[] bytes = (byte[]) is.readObject();

                ht.put(key, decode(bytes));
            }
        } catch (ObjectStreamException e) {
            Debug.trace("Key " + key); // would be nice to know object type.
            throw e;
        } catch (IOException e) {
            Debug.trace("Key " + key); // would be nice to know object type.
            throw e;
        } catch (ClassNotFoundException e) {
            Debug.trace("Key " + key); // would be nice to know object type.
            throw e;
        }

        return ht;
    }

    /**
     * Implements IDBAttrMapper.mapLDAPAttributeSetToObject
     * <p>
     *
     * @see IDBAttrMapper#mapLDAPAttributeSetToObject
     */
    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs,
            String name, IDBObj parent)
            throws EBaseException {
        Hashtable<String, Object> ht = null;

        //
        // Data is stored in a (single valued) binary attribute
        //
        byte[] value;

        LDAPAttribute attr = null;

        try {
            attr = attrs.getAttribute(Schema.LDAP_ATTR_REQUEST_ATTRS);

            if (attr != null) {
                @SuppressWarnings("unchecked")
                Enumeration<byte[]> values = attr.getByteValues();

                value = values.nextElement();

                ht = decodeHashtable(value);
            }
        } catch (Exception x) {
            Debug.trace("Mapping error in request Id " +
                    ((RequestRecord) parent).getRequestId().toString() + " : " + x);
            Debug.trace("Attr " + attr.getName());
            //if (Debug.ON) {
            Debug.printStackTrace(x);
            //}
        }

        parent.set(name, ht);
    }

    public String mapSearchFilter(String name, String op, String value) {
        return Schema.LDAP_ATTR_REQUEST_ID + op + value;
    }

    protected final static Vector<String> mAttrs = new Vector<String>();

    static {
        mAttrs.add(Schema.LDAP_ATTR_REQUEST_ATTRS);
    }
}

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
 *
 */
class ExtAttrDynMapper implements IDBDynAttrMapper {

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
            if (input[index] == '-') {
                if (((index + 1) < input.length) &&
                        (input[index + 1] == '-')) {
                    if (output == null) {
                        output = new StringBuffer(input.length);
                    }
                    output.append(input, startCopyIndex, index - startCopyIndex);
                    index += 2;
                    if ((index + 3) < input.length) {
                        output.append(
                                Character.toChars(
                                        Integer.parseInt(new String(input, index, 4),
                                                16))
                                );
                    }
                    index += 4;
                    startCopyIndex = index;
                } else {
                    index++;
                }
            } else {
                index++;
            }
        }

        if (output == null) {
            return key;
        } else {
            output.append(input, startCopyIndex, index - startCopyIndex);
            return output.toString();
        }
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
            if (!isAlphaNum(input[index])) {
                if ((input[index] == '-') &&
                        ((index + 1) < input.length) &&
                        (isAlphaNum(input[index + 1]))) {
                    index += 2;
                } else if ((input[index] == '-') &&
                           ((index + 1) == input.length)) {
                    index += 1;
                } else {
                    if (output == null) {
                        output = new StringBuffer(input.length + 5);
                    }
                    output.append(input, startCopyIndex, index - startCopyIndex);
                    while ((index < input.length) &&
                            (!isAlphaNum(input[index]))) {
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
            } else {
                index++;
            }
        }

        if (output == null) {
            return key;
        } else {
            output.append(input, startCopyIndex, index - startCopyIndex);
            return output.toString();
        }
    }

    protected boolean isAlphaNum(char in) {
        if ((in >= 'a') && (in <= 'z')) {
            return true;
        }
        if ((in >= 'A') && (in <= 'Z')) {
            return true;
        }
        if ((in >= '0') && (in <= '9')) {
            return true;
        }
        return false;
    }

    public void mapObjectToLDAPAttributeSet(IDBObj parent, String name,
                                            Object obj, LDAPAttributeSet attrs)
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
                String stringValue = (String) value;
                attrs.add(new LDAPAttribute(
                        extAttrPrefix + encodeKey(key),
                        stringValue));
            } else if (value instanceof Hashtable) {
                @SuppressWarnings("unchecked")
                Hashtable<String, String> innerHash = (Hashtable<String, String>) value;
                Enumeration<String> innerHashEnum = innerHash.keys();
                while (innerHashEnum.hasMoreElements()) {
                    String innerKey = innerHashEnum.nextElement();
                    String innerValue = innerHash.get(innerKey);
                    attrs.add(new LDAPAttribute(
                            extAttrPrefix + encodeKey(key) + ";" + encodeKey(innerKey),
                            innerValue));
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    public void mapLDAPAttributeSetToObject(LDAPAttributeSet attrs, String name,
                                            IDBObj parent)
            throws EBaseException {
        Hashtable<String, Object> ht = new Hashtable<String, Object>();
        Hashtable<String, String> valueHashtable;

        Enumeration<LDAPAttribute> attrEnum = attrs.getAttributes();
        while (attrEnum.hasMoreElements()) {
            LDAPAttribute attr = attrEnum.nextElement();
            String baseName = attr.getBaseName();
            if (baseName.toLowerCase().startsWith(extAttrPrefix)) {
                String keyName = decodeKey(
                        baseName.substring(extAttrPrefix.length()));
                String[] subTypes = attr.getSubtypes();
                String[] values = attr.getStringValueArray();
                if (values.length != 1) {
                    String message = "Output Mapping Error in request ID " +
                            ((IRequestRecord) parent).getRequestId().toString() + " : " +
                            "more than one value returned for " +
                            keyName;
                    Debug.trace(message);
                    throw new EBaseException(message);
                }
                if ((subTypes != null) && (subTypes.length > 0)) {
                    if (subTypes.length != 1) {
                        String message = "Output Mapping Error in request ID " +
                                ((IRequestRecord) parent).getRequestId().toString() + " : " +
                                "more than one subType returned for " +
                                keyName;
                        Debug.trace(message);
                        throw new EBaseException(message);
                    }
                    Object value = ht.get(keyName);
                    if ((value != null) && (!(value instanceof Hashtable))) {
                        String message = "Output Mapping Error in request ID " +
                                ((IRequestRecord) parent).getRequestId().toString() + " : " +
                                "combined no-subtype and subtype data for key " +
                                keyName;
                        Debug.trace(message);
                        throw new EBaseException(message);
                    }
                    valueHashtable = (Hashtable<String, String>) value;
                    if (valueHashtable == null) {
                        valueHashtable = new Hashtable<String, String>();
                        ht.put(keyName, valueHashtable);
                    }
                    valueHashtable.put(decodeKey(subTypes[0]), values[0]);
                } else {
                    ht.put(keyName, values[0]);
                }
            }
        }

        parent.set(name, ht);
    }

    public String mapSearchFilter(String name, String op, String value) throws EBaseException {
        return name + op + value;
    }

    protected final static String extAttrPrefix = "extdata-";

    protected final static Vector<String> mAttrs = new Vector<String>();

    static {
        mAttrs.add(Schema.LDAP_ATTR_EXT_ATTR);
    }
}
