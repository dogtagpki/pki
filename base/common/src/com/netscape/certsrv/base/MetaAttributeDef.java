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
package com.netscape.certsrv.base;

import java.util.Enumeration;
import java.util.Hashtable;

import netscape.security.util.ObjectIdentifier;

/**
 * A class representing a meta attribute defintion.
 * <P>
 *
 * @version $Revision$, $Date$
 */
public class MetaAttributeDef {

    private String mName;
    private ObjectIdentifier mOid;
    private Class<?> mValueClass;
    private static Hashtable<String, MetaAttributeDef> mNameToAttrDef = new Hashtable<String, MetaAttributeDef>();
    private static Hashtable<ObjectIdentifier, MetaAttributeDef> mOidToAttrDef =
            new Hashtable<ObjectIdentifier, MetaAttributeDef>();

    private MetaAttributeDef() {
    }

    /**
     * Constructs a MetaAttribute defintion
     * <P>
     *
     * @param name attribute name
     * @param valueClass attribute value class
     * @param oid attribute object identifier
     */
    private MetaAttributeDef(String name, Class<?> valueClass,
            ObjectIdentifier oid) {
        mName = name;
        mValueClass = valueClass;
        mOid = oid;
    }

    /**
     * Gets an attribute OID.
     * <P>
     *
     * @return returns attribute OID or null if not defined.
     */
    public ObjectIdentifier getOID() {
        return mOid;
    }

    /**
     * Gets an Java class for the attribute values
     * <P>
     *
     * @return returns Java class for the attribute values
     */
    public Class<?> getValueClass() {
        return mValueClass;
    }

    /**
     * Gets attribute name
     * <P>
     *
     * @return returns attribute name
     */
    public String getName() {
        return mName;
    }

    /**
     * Registers new MetaAttribute defintion
     * Attribute is defined by name, Java class for attribute values and
     * optional object identifier
     * <P>
     *
     * @param name attribute name
     * @param valueClass attribute value class
     * @param oid attribute object identifier
     * @exception IllegalArgumentException if name or valueClass are null, or
     *                conflicting attribute definition already exists
     */
    public static MetaAttributeDef register(String name, Class<?> valueClass,
            ObjectIdentifier oid) {
        if (name == null) {
            throw new IllegalArgumentException(
                    "Attribute name must not be null");
        }
        if (valueClass == null) {
            throw new IllegalArgumentException(
                    "Attribute value class must not be null");
        }

        MetaAttributeDef newDef = new MetaAttributeDef(name, valueClass, oid);
        MetaAttributeDef oldDef;

        if ((oldDef = mNameToAttrDef.get(name)) != null &&
                !oldDef.equals(newDef)) {
            throw new IllegalArgumentException(
                    "Attribute \'" + name + "\' is already defined");
        }
        if (oid != null &&
                (oldDef = mOidToAttrDef.get(oid)) != null &&
                !oldDef.equals(newDef)) {
            throw new IllegalArgumentException(
                    "OID \'" + oid + "\' is already in use");
        }
        mNameToAttrDef.put(name, newDef);
        if (oid != null) {
            mOidToAttrDef.put(oid, newDef);
        }
        return newDef;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((mName == null) ? 0 : mName.hashCode());
        result = prime * result + ((mOid == null) ? 0 : mOid.hashCode());
        result = prime * result + ((mValueClass == null) ? 0 : mValueClass.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        MetaAttributeDef other = (MetaAttributeDef) obj;
        if (mName == null) {
            if (other.mName != null)
                return false;
        } else if (!mName.equals(other.mName))
            return false;
        if (mOid == null) {
            if (other.mOid != null)
                return false;
        } else if (!mOid.equals(other.mOid))
            return false;
        if (mValueClass == null) {
            if (other.mValueClass != null)
                return false;
        } else if (!mValueClass.equals(other.mValueClass))
            return false;
        return true;
    }

    /**
     * Retrieves attribute definition by name
     * <P>
     *
     * @param name attribute name
     * @return attribute definition or null if not found
     */
    public static MetaAttributeDef forName(String name) {
        return mNameToAttrDef.get(name);
    }

    /**
     * Retrieves attribute definition by object identifier
     * <P>
     *
     * @param oid attribute object identifier
     * @return attribute definition or null if not found
     */
    public static MetaAttributeDef forOID(ObjectIdentifier oid) {
        return mOidToAttrDef.get(oid);
    }

    /**
     * Returns enumeration of the registered attribute names
     * <P>
     *
     * @return returns enumeration of the registered attribute names
     */
    public static Enumeration<String> getAttributeNames() {
        return mNameToAttrDef.keys();
    }

    /**
     * Returns enumeration of the registered attribute object identifiers
     * <P>
     *
     * @return returns enumeration of the attribute object identifiers
     */
    public static Enumeration<ObjectIdentifier> getAttributeNameOids() {
        return mOidToAttrDef.keys();
    }
}
