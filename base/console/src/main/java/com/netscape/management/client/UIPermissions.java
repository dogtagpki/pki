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
package com.netscape.management.client;

import java.util.*;
import javax.swing.event.*;
import netscape.ldap.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;

/**
* Defines a set of UI elements and their properties.
*/
public class UIPermissions
{
    private int NAME = 0;
    private int DESCRIPTION = 1;
    private Hashtable h = null;
    private String basePermissionDN = null;
    private String permissionDN = null;
    private Vector changeListeners = null;
    private LDAPConnection ldc = null;
    private String ENTRY_PREFIX = "cn";

    /**
     * Constructs a UIPermissions object with an
     * appropriate Permissions DN based on the 
     * Server Instance Entry (SIE) location.
     */
    public UIPermissions()
    {
        // TODO: calculate sie dn
        this(null);
    }

    /**
     * Constructs a UIPermissions object with the
     * specified base DN to be used for storing 
     * permissions.
     */
    public UIPermissions(String dn)
    {
        h = new Hashtable();
        ConsoleInfo ci = Console.getConsoleInfo();
        if(ci != null)
            ldc = ci.getLDAPConnection();
        if(dn != null)
            setPermissionBaseDN(dn);
    }

    /**
     * Adds a permission defination to the set of 
     * UI permissions.
     * 
     * @param id     non-localized unique permission ID
     * @param name   localized name (one or two words)
     * @param description localized description (one or two sentences)
     *  
     */
    public void addPermission(String id, String name, String description)
    {
        Vector nd = new Vector();
        Vector changeListeners = new Vector();
        nd.insertElementAt(name, NAME);
        nd.insertElementAt(description, DESCRIPTION);
        h.put(id, nd);
    }
    
    /**
     * Removes a permission from the set of UI permissions.
     * 
     * @param id   the ID of the permission to remove
     */
    public void removePermission(String id)
    {
        h.remove(id);
    }
    
    /**
     * Checks whether the currently authenticated user 
     * can access the permission specified by the ID.
     * 
     * @param permissionID  the ID of the permission to check
     */
    public boolean hasPermission(String permissionID)
    {
        boolean result = false;
        Debug.print("UIPermissions: " + permissionID + " ");
        if((permissionID != null) &&
           (permissionDN != null) && 
           (ldc != null) && (ldc.isConnected()))
        {
            try
            {
                LDAPEntry entry = ldc.read(ENTRY_PREFIX + "=" + permissionID + "," + permissionDN);
                if(entry != null)
                    result = true;
            }
            catch(LDAPException e)
            {
                switch(e.getLDAPResultCode())
                {
                    case LDAPException.NO_SUCH_OBJECT:
                        result = true;
                        break;
                            
                    case LDAPException.INSUFFICIENT_ACCESS_RIGHTS:
                    default:
                        result = false;
                        break;
                }
            }
        }
        Debug.println(result ? "yes" : "no");
        return result;
    }

    /**
     * Retrieves the base directory location under which 
     * permission entries being stored.
     *
     * @return a string representing the DN to store permissions
     */
    public String getPermissionBaseDN()
    {
        return basePermissionDN;
    }

    /**
     * Sets the base directory location where permissions 
     * should be stored.
     *
     * @return a string representing the DN to store permissions
     */
    public void setPermissionBaseDN(String basePermissionDN)
    {
        this.basePermissionDN = basePermissionDN;
        permissionDN = createEntry("UI", basePermissionDN);
    }

    /**
     * Retrieves a non-localized identifier for the UI element
     * at the specified index.
     *
     * @return non-localized string ID for UI element
     * @param integer index of the UI element
     */
    public Enumeration getPermissionIDs()
    {
        return h.keys();
    }

    /**
     * Retrieves a localized name for a specific UI element.
     * This text is a one or two word name to
     * be displayed in the UI (provided by Console)
     * that allows the user to set permissions on UI elements.
     *
     * @return localized string name for UI element
     * @param integer index of the UI element
     */
    public String getName(String permissionID)
    {
        String result = null;
        Vector nd = (Vector)h.get(permissionID);
        if(nd != null)
            result = (String)nd.elementAt(NAME);
        return result;
    }

    /**
     * Retrieves a localized description for a specific UI element.
     * This text is a one or two sentence description to
     * be displayed in the UI (provided by Console)
     * that allows the user to set permissions on UI elements.
     *
     * @return localized string description for UI element
     * @param integer index of the UI element
     */
    public String getDescription(String permissionID)
    {
        String result = null;
        Vector nd = (Vector)h.get(permissionID);
        if(nd != null)
            result = (String)nd.elementAt(DESCRIPTION);
        return result;
    }
    
    /**
     * Notification that a permission has changed at runtime.
     * Typically this will occur when the user changes the
     * permissions through the UI.  Any registered change
     * listeners are notified.
     *
     * In response to those notifications, the specific UI
     * element's permission should be evaluated again and 
     * its visibility adjusted accordingly.
     *
     * The ChangeEvent object contains the permission ID 
     * string as its source.
     *
     * @param integer index of the UI element
     */
    public void permissionChanged(String permissionID)
    {
        Enumeration e = changeListeners.elements();
        while(e.hasMoreElements())
        {
            ChangeListener l = (ChangeListener)e.nextElement();
            l.stateChanged(new ChangeEvent(permissionID));
        }
    }

    /**
     * Registers a ChangeListener that receives 
     * notifications when a permission changes.
     *
     * In response to such a notification, the specific UI
     * element's permission should be evaluated again and 
     * its visibility adjusted accordingly.
     *
     * The ChangeEvent object contains the permission ID 
     * string as its source.
     */
    public void addChangeListener(ChangeListener l)
    {
        changeListeners.addElement(l);
    }

    /**
     * Unregisters a ChangeListener that receives 
     * notifications when a permission changes.
     */
    public void removeChangeListener(ChangeListener l)
    {
        changeListeners.addElement(l);
    }
    
    private String createEntry(String entryName, String basePermissionDN)
    {
        String entryDN = ENTRY_PREFIX + "=" + entryName + "," + basePermissionDN;
        try 
        {
            ldc.search(entryDN, LDAPConnection.SCOPE_SUB, "(objectclass=*)", null, false);
        } 
        catch (LDAPException e) 
        {
            switch(e.getLDAPResultCode())
            {
                case LDAPException.NO_SUCH_OBJECT:
                    try 
                    {
                        LDAPAttributeSet attrs = new LDAPAttributeSet();
                        attrs.add(new LDAPAttribute(ENTRY_PREFIX, entryName));
                        attrs.add(new LDAPAttribute("objectclass", "top"));
                        attrs.add(new LDAPAttribute("objectclass", "nsAdminConsoleUser"));
                        ldc.add(new LDAPEntry(entryDN, attrs));
                    } 
                    catch (LDAPException exception) 
                    {
                        Debug.println("Cannot create: " + entryDN);
                    }
                    break;
                            
                default:
                    break;
            }
        }
        return entryDN;
    }
    
    public String getPermissionDN(String permissionID)
    {
        return createEntry(permissionID, permissionDN);
    }
}
