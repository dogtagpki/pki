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
package com.netscape.management.client.topology.customview;

import com.netscape.management.client.topology.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;
import java.util.*;
import netscape.ldap.*;

/**
 * data structure for a custom view
 */
public class ViewInfo {
    boolean isAdded = false;
    boolean isDeleted = false;
    boolean isRenamed = false;
    boolean isModified = false;
    boolean isPublic = false;
    String viewID;
    String displayName;
    String className;
    boolean isPlugin;
    LDAPEntry ldapEntry;

    /**
     * creates a ViewInfo object initialized with the specified data.
     *
     * @param viewID unique ID
     * @param displayName display name
     * @param className associated java class name
     */
    public ViewInfo(String id, String displayName, String className) {
        this.viewID = id;
        this.displayName = displayName;
        this.className = className;
        
        this.isPlugin = false;
    }

    /**
     * creates a ViewInfo object from an LDAPEntry
     *
     * @param ldapEntry an ldapEntry that represents the view
     */    
    public ViewInfo(LDAPEntry ldapEntry) {
        
        this.ldapEntry = ldapEntry;

        viewID      = getFirstAttributeValue(ldapEntry, "cn");
        displayName = getFirstAttributeValue(ldapEntry, "nsDisplayName");
        if (displayName == null) {
            displayName = viewID;
        }
        className   = getFirstAttributeValue(ldapEntry, "nsClassName");
        
        // A plugin does not have object class nsTopologyCustomView
        isPlugin = ! hasAttributeValue(ldapEntry, "objectclass", "nsTopologyCustomView");
        
    }
    
    /**
      * return the first attribute value of the LDAP entry
      *
      * @param ldapEntry LDAP Entry
      * @param name name of the attribute to be retrieved
      * @return the first value of the attribute
      */
    static String getFirstAttributeValue(LDAPEntry ldapEntry,
            String name) {
        LDAPAttribute attr = ldapEntry.getAttribute(name);
        if (attr != null) {
            Enumeration attr_enum = attr.getStringValues();
            if (attr_enum != null)
                try {
                    return (String) attr_enum.nextElement();
                } catch (Exception e)// if value stored was null, enum fails
                {
                }
        }
        return null;
    }

    /**
      * Check if an attribute has a specifuc value
      *
      * @param ldapEntry LDAP Entry
      * @param name name of the attribute to be retrieved
      * @param value value to be searched for (case ignored)
      * @return a flag whether the value was found
      */
    static boolean hasAttributeValue(LDAPEntry ldapEntry,
            String name, String value) {
        LDAPAttribute attr = ldapEntry.getAttribute(name);
        if (attr != null) {
            Enumeration attr_enum = attr.getStringValues();
            while (attr_enum.hasMoreElements()) {
                String v = (String)attr_enum.nextElement();
                if (v.equalsIgnoreCase(value)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
    * is it a public custom view
    * @return true if public view
    */
    public boolean isPublic() {
        return isPublic;
    };

    /**
     * sets if this view is global
     * @param isPublic status of the custom view
     */
    public void setPublic(boolean isPublic) {
        this.isPublic = isPublic;
    };

    /**
     * get id
     * @return ID for the custom view
     */
    public String getID() {
        return viewID;
    };

    /**
     * get display name
     * @return display name for the custom view
     */
    public String getDisplayName() {
        return displayName;
    };

    /**
     * get class name
     * @return associated java class for the custom view
     */
    public String getClassName() {
        return className;
            };

    /**
     * is the custom view newly added
     *
     * @return true if yes
     */
    public boolean isAdded() {
        return isAdded;
    };

    /**
     * has this view been deleted?
     *
     * @return true if view has been deleted
     */
    public boolean isDeleted() {
        return isDeleted;
    };

    /**
     * has this view been renamed?
     *
     * @return true if view has been renamed
     */
    public boolean isRenamed() {
        return isRenamed;
    };

    /**
     * has this view been modified?
     *
     * @return true if view has been modified
     */
    public boolean isModified() {
        return isModified;
    };

    /**
     * set the id
     *
     * @param id new custom view id
     */
    public void setViewID(String id) {
        viewID = id;
    };

    /**
     * set the display name
     *
     * @param displayName new custom view display name
     */
    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    };

    /**
     * set the associated java class name
     *
     * @param className new custom view class name
     */
    public void setClassName(String className) {
        this.className = className;
            };

            /**
             * set the custom view is added
             *
             * @param added true if the custom view is added
             */
    public void setAdded(boolean added) {
        isAdded = added;
    };

    /**
     * set the ldap entry
     *
     * @param ldapEntry an ldapEntry that corresponds to this view
     */
    public void setLdapEntry(LDAPEntry ldapEntry) {
        this.ldapEntry = ldapEntry;
    };


    /**
     * set the custom view is deleted
     *
     * @param deleted true if the custom view is deleted
     */
    public void setDeleted(boolean deleted) {
        this.isDeleted = deleted;
        setAdded(false);
    };

    /**
     * set the custom view is renamed
     *
     * @param renamed true if the custom view is renamed
     */
    public void setRenamed(boolean renamed) {
        this.isRenamed = renamed;
    };

    /**
     * set the custom view is modified
     *
     * @param modified true if the custom view is modified
     */
    public void setModified(boolean modified) {
        this.isModified = modified;
    };

    /**
     * return the display name
     *
     * @return display name
     */
    public String toString() {
        return getDisplayName();
    }

    /**
    * get the java class instance for the associated custom view
    *
    * @return custom view java instance
    */
    public ICustomView getClassInstance() {
    
        if (!isPlugin && ldapEntry != null) {
            return new CustomView(ldapEntry);
        }
        else if (className == null) {
            return null;
        }

        Class c = ClassLoaderUtil.getClass(Console.getConsoleInfo(), className);
        if (c != null) {
            try {
                return (ICustomView) c.newInstance();
            }
            catch (Exception e) {
                Debug.println("ViewInfo.getClassInstance() " + className  + " " + e);
            }
        }
        return null;        
    }
}
