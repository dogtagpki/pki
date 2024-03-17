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

import javax.swing.*;
import com.netscape.management.client.util.*;


/**
 * The Resource Editor is presented to the administrator as a series of
 * editable pages. Each page contains different information for the same
 * resource. For example, the "user" resource may contain a page for the
 * user's general information, i.e. name, unique ID, and phone. It may
 * also contain a separate page which describes all services the user is
 * licensed to use. Each page is a plugin to the Resource Editor, and it
 * must implement the IResourceEditorPage interface. DefaultResEditorPage
 * provides a minimal implementation for this interface, and can be used
 * as the base class for all subsequent plugins (pages).
 */
public class DefaultResEditorPage extends JPanel implements IResourceEditorPage {

    PickerEditorResourceSet _resource = new PickerEditorResourceSet();


    /**
     * Implements the IResourceEditorPage interface.
      * Initializes the page with context information. It will be called once
      * the page is added to resource editor.
     *
     * @param observable  the observable object
     * @param parent      the resource editor container
     */
    public void initialize(ResourcePageObservable observable,
            ResourceEditor parent) {
    }


    /**
      * Implements the IResourceEditorPage interface.
       * Returns unique ID string which identifies the page.
      *
      * @return  unique ID for the page
      */
    public String getID() {
        return _resource.getString("resourceEditor", "defaultID");
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Saves all modified information to the observable object
      *
      * @param observable     the observable object
      * @return               true if save succeeded; false otherwise
      * @exception Exception
       */
    public boolean save(ResourcePageObservable observable)
            throws Exception {
        return true;
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Handle some post save condition. This is called after the
      * information is saved and the object has been created in
      * the directory server.
      *
      * @param observable     the observable object
      * @return               true if save succeeded; false otherwise
      * @exception Exception
       */
    public boolean afterSave(ResourcePageObservable observable)
            throws Exception {
        return true;
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Resets information on the page.
       */
    public void reset() {
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Clears all information on the page.
       */
    public void clear() {
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Sets default information on the page.
       */
    public void setDefault() {
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Specifies whether any information on the page has been modified.
      *
      * @return  true if some information has been modified; false otherwise
       */
    public boolean isModified() {
        return false;
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Sets the modified flag for the page.
      *
      * @param value  true or false
       */
    public void setModified(boolean value) {
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Specifies whether the information on the page is read only.
      *
      * @return  true if some information has been modified; false otherwise
       */
    public boolean isReadOnly() {
        return true;
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Sets the read only flag for the page.
      *
      * @param value  true or false
       */
    public void setReadOnly(boolean value) {
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Sets the enabled flag for the page.
      *
      * @param value  true or false
       */
    public void setEnable(boolean value) {
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Specifies whether all required information has been provided for
      * the page.
      *
      * @return  true if all required information has been provided; false otherwise
       */
    public boolean isComplete() {
        return true;
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Returns a brief name for the page. The name should reflect the
      * plugin page.
       */
    public String getDisplayName() {
        return _resource.getString("resourceEditor", "defaultDisplayName");
    }


    /**
       * Implements the IResourceEditorPage interface.
      * Displays help information for the page
       */
    public void help() {
        Help help = new Help(_resource);
        help.contextHelp("ug","DefaultResEditorPage");
    }
}
