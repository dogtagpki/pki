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
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import com.netscape.certsrv.base.EBaseException;
import com.netscape.certsrv.dbs.IDBAttrMapper;
import com.netscape.certsrv.dbs.IDBObj;
import com.netscape.certsrv.request.RequestId;
import com.netscape.cmscore.apps.CMS;

import netscape.ldap.LDAPAttribute;
import netscape.ldap.LDAPAttributeSet;

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
public class RequestAttrsMapper implements IDBAttrMapper {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(RequestAttrsMapper.class);

    protected final static Vector<String> mAttrs = new Vector<String>();

    static {
        mAttrs.add(Schema.LDAP_ATTR_REQUEST_ATTRS);
    }

    public Enumeration<String> getSupportedLDAPAttributeNames() {
        return mAttrs.elements();
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
                    logger.warn("RequestRecord: attribute '" + key + "' is not serializable: "
                            + x.getMessage(), x);

                } catch (Exception x) {
                    logger.warn("RequestRecord: attribute '" + key + "' - error during serialization: "
                            + x.getMessage(), x);
                }
            }

            os.writeObject(null);

        } catch (Exception x) {
            if (parent != null) {
                RequestId requestID = ((RequestRecord) parent).getRequestId();
                logger.error("Output Mapping Error in requeset ID " +
                        requestID + " : " + x.getMessage(), x);
            }
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

        attrs.add(new LDAPAttribute(Schema.LDAP_ATTR_REQUEST_ATTRS, bos.toByteArray()));
    }

    private byte[] encode(Object value) throws NotSerializableException, IOException {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(bos);

        os.writeObject(value);
        os.close();

        return bos.toByteArray();
    }

    private Object decode(byte[] data) throws ObjectStreamException, IOException, ClassNotFoundException {

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
            logger.error("Key " + key + ": " + e.getMessage(), e);
            throw e;

        } catch (IOException e) {
            logger.error("Key " + key + ": " + e.getMessage(), e);
            throw e;

        } catch (ClassNotFoundException e) {
            logger.error("Key " + key + ": " + e.getMessage(), e);
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
    public void mapLDAPAttributeSetToObject(
            LDAPAttributeSet attrs,
            String name,
            IDBObj parent)
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
            RequestId requestID = ((RequestRecord) parent).getRequestId();
            logger.warn("Mapping error in request Id " +
                    requestID + " : " + x.getMessage(), x);
            logger.trace("Attr " + attr.getName());
        }

        parent.set(name, ht);
    }

    public String mapSearchFilter(String name, String op, String value) {
        return Schema.LDAP_ATTR_REQUEST_ID + op + value;
    }
}
