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
 * IResourceEditorPage interface defines the methods that must be supported
 * by all ResourceEditor plugins. Each plugin is identified by its own ID.
 * The ResourceEditor will initialize each page with the context information
 * needed by each plugin.
 *
 * @see ResourceEditor
 * @see ResourcePageObservable
 */
public interface IResourceEditorPage {

    /**
     * Initializes the page with context information. It will be called once
     * the page is added to resource editor.
     *
     * @param observable  the observable object
     * @param parent      the resource editor container
     */
    public abstract void initialize(ResourcePageObservable observable,
            ResourceEditor parent);


    /**
     * Returns unique ID string which identifies the page.
     *
     * @return  unique ID for the page
     */
    public abstract String getID();


    /**
     * Saves all modified information to the observable object.
     *
     * @param observable     the observable object
     * @return               true if save succeeded; false otherwise
     * @exception Exception
     */
    public abstract boolean save(ResourcePageObservable observable)
            throws Exception;


    /**
     * Handle some post save condition. This is called after the
     * information is saved and the object has been created in
     * the directory server.
     *
     * @param observable     the observable object
     * @return               true if save succeeded; false otherwise
     * @exception Exception
     */
    public abstract boolean afterSave(
            ResourcePageObservable observable) throws Exception;


    /**
     * Resets information on the page.
     */
    public abstract void reset();


    /**
     * Clears all information on the page.
     */
    public abstract void clear();


    /**
     * Sets default information on the page.
     */
    public abstract void setDefault();


    /**
     * Specifies whether any information on the page has been modified.
     *
     * @return  true if some information has been modified; false otherwise
     */
    public abstract boolean isModified();


    /**
     * Sets the modified flag for the page.
     *
     * @param value  true or false
     */
    public abstract void setModified(boolean value);


    /**
     * Specifies whether the information on the page is read only.
     *
     * @return  true if some information has been modified; false otherwise
     */
    public abstract boolean isReadOnly();


    /**
     * Sets the read only flag for the page.
     *
     * @param value  true or false
     */
    public abstract void setReadOnly(boolean value);


    /**
     * Sets the enabled flag for the page.
     *
     * @param value  true or false
     */
    public abstract void setEnable(boolean value);


    /**
     * Specifies whether all required information has been provided for
     * the page.
     *
     * @return  true if all required information has been provided; false otherwise
     */
    public abstract boolean isComplete();


    /**
     * Returns a brief name for the page. The name should reflect the
     * plugin page.
     */
    public abstract String getDisplayName();


    /**
     * Displays help information for the page
     */
    public abstract void help();
}
