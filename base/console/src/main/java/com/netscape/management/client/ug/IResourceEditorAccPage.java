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
package com.netscape.management.client.ug;


/**
 * IResourceEditorAccPage interface defines the required methods for a
 * specific type of resource editor plugin. This plugin can be used for
 * adding or removing accounts, which are needed to gain access to
 * resources such as workstations, server software, etc.
 */
public interface IResourceEditorAccPage {
    /**
      * Retrieves the object class associated with this page.
      *
      * @return  an array of object class names
      */
    public abstract String[] getAssociatedObjectClass();


    /**
     * Retrieves the name to display for the account.
     *
     * @return  the name to display for the account
     */
    public abstract String getAccountDisplayName();


    /**
     * Add an account to the observable object.
     *
     * @param observable  the observable object
     */
    public abstract void addAccount(ResourcePageObservable observable);


    /**
     * Remove an account from the observable object.
     *
     * @param observable  the observable object
     */
    public abstract void removeAccount(ResourcePageObservable observable);
}

