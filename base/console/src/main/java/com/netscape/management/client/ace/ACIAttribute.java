/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *                                                                                 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *                                                                                 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.ace;

/**
 * A class that encapsulates one attribute of an ACI.
 * The attribute contains three data elements:
 * <name>
 * <operator>
 * <value>
 * 
 * For example, in the aci:
 * (targetfilter=(o=NetscapeRoot))
 * <name> is "targetfilter"
 * <operator> is "="
 * <value is "(o=NetscapeRoot)"
 * 
 * This class is used by the ACIParser when it tokenizes
 * an ACI String.  The resulting ACIAttribute objects
 * are stored in a Vector and made available to each tab.
 * 
 * @see IACITab#aciChanged
 */
public class ACIAttribute
{
    String name = null;
    String operator = null;
    String value = null;
    int startIndex = 0;
    int endIndex = 0;

    
    /**
     * Contructs an ACIAttribute with the specified name.
     * The operator and value properties are set to null.
     * This constructor is useful for creating a dummy
     * ACIAttribute for comparison purposes.
     * 
     * @param name          the name for this attribute
     * @see #equals
     */
    public ACIAttribute(String name)
    {
        this(name, null, null);
    }

    /**
     * Constructs an ACIAttribute with specified properties.
     * The begining and ending index values are set to 0.
     * 
     * @param name          the name for this attribute
     * @param operator      the operator for this attribute
     * @param value         the value for this attribute
     */
    public ACIAttribute(String name, String operator, String value)
    {
        this(name, operator, value, 0, 0);
    }
    
    /**
     * Constructs an ACIAttribute with specified properties.
     * 
     * @param name          the name for this attribute
     * @param operator      the operator for this attribute
     * @param value         the value for this attribute
     * @param startIndex    the begining position for this ACI Attribute
     * @param endIndex      the ending position for this ACI Attribute
     */
    public ACIAttribute(String name, String operator, String value, int startIndex, int endIndex)
    {
        this.name = name;
        this.operator = operator;
        this.value = value;
        this.startIndex = startIndex;
        this.endIndex = endIndex;
    }
    
    /**
     * Sets name for this ACIAttribute.
     * 
     * @param name the name for this attribute
     */
    public void setName(String name)
    {
        this.name = name;
    }
    
    /**
     * Sets operator for this ACIAttribute.
     * 
     * @param operator the operator for this attribute
     */
    public void setOperator(String operator)
    {
        this.operator = operator;
    }
    
    /**
     * Sets value for this ACIAttribute.
     * 
     * @param value the value for this attribute
     */
    public void setValue(String value)
    {
        this.value = value;
    }
    
    /**
     * Retrives name of this ACIAttribute.
     * 
     * @return the name for this attribute
     */
    public String getName()
    {
        return name;
    }
    
    /**
     * Retrieves operator of this ACIAttribute.
     * May be null, in the case of "version 3.0".
     * 
     * @return the operator for this attribute
     */
    public String getOperator()
    {
        return operator;
    }
    
    /**
     * Retrieves operator of this ACIAttribute.
     * 
     * @return the value for this attribute
     */
    public String getValue()
    {
        return value;
    }
    
    /**
     * Retrives String representation of this ACIAttribute.
     * 
     * @return string containing name, operator, and value
     */
    public String toString()
    {
        String n = name;
        String o = operator;
        String v = value;
        if(n == null) n = "";
        if(o == null) o = " ";
        if(v == null) v = "";
        if(o.length() == 0)
            o="~";
        
        return startIndex + "," + endIndex + ": " + n + o + v;
    }
    
    /**
     * Compares the specified object to this ACIAttribute.
     * @param x if object is of type ACIAttribute, its name is compared.
     *          otherwise, super.equals(x) is called.
     * 
     * @return true if objects are equal
     */
    public boolean equals(Object x)
    {
        if(x instanceof ACIAttribute)
            return ((ACIAttribute)x).getName().equals(name);
        return super.equals(x);
    }
    /**
     * Sets the begining value of this range.
     * 
     * @param index the begining value of this range.
     */
    public void setStartIndex(int index)
    {
        startIndex = index;
    }
    
    /**
     * Returns the begining value of this range.
     * 
     * @return the begining value of this range.
     */
    public int getStartIndex()
    {
        return startIndex;
    }

    /**
     * Sets the ending value of this range.
     * 
     * @param index the ending position for this ACI Attribute
     */
    public void setEndIndex(int index)
    {
        endIndex = index;
    }
    
    /**
     * Returns the ending value of this range.
     * 
     * @return the ending value of this range.
     */
    public int getEndIndex()
    {
        return endIndex;
    }
    
    /**
     * Converts a vector of ACIAttribute objects into an array.
     * @return an array of ACIAttribute objects
     */
    public static ACIAttribute[] toArray(java.util.Vector attrVector)
    {
        ACIAttribute[] array = new ACIAttribute[attrVector.size()];  // TODO: JDK 1.1
        attrVector.copyInto(array);
        return array;
        
        // return ACIAttribute[] attrVector.toArray(); // TODO: JDK 1.2
    }
    
    /**
     * Returns the ACIAttribute that matches the name.
     * Returns null if an ACIAttribute of the specified name does not exist.
     * 
     * @param name              the name of the ACIAttribute to match
     * @param aciAttributes     the array of ACIAttributes to search
     * @return the ACIAttribute that matches the name.
     */
    public static ACIAttribute getAttribute(String name, ACIAttribute[] aciAttributes)
    {
        if(aciAttributes != null)
        {
            for(int i = 0; i < aciAttributes.length; i++)
            {
                ACIAttribute attr = aciAttributes[i];
                if(attr.getName().equals(name))
                    return attr;
            }
        }
        return null;
    }
}
