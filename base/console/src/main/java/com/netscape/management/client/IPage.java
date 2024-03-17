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

/**
  * A class that specifies properties and functionality for a tab
  * that appears in the Console window.  This interface is
  * usually implemented by an object that extends a Component.
  *
  * @see IFrameworkInitializer
  * @see IFramework
  */
public interface IPage {
    /**
      * Initializes object; called after construction and cloning.
      * The IFramework parameter references the instance of the
      * Console window that uses this object.  This parameter is
      * used in methods and events that communicate with the Console
      * window.  For example, adding menu items, setting the status
      * bar, etc.
      *
      * @param parent	the IFramework parent of this object
      */
    public abstract void initialize(IFramework parent);

    /**
     * Returns IFramework object that is parent of this object.
     * The implementation of this method should return
     * the parameter specified in the initialize method.
     *
     * @return an IFramework object representing parent Console window.
     */
    public abstract IFramework getFramework();

    /**
     * Defines the title for this tab.  This title appears on the
     * tab selector in the Console window.
     *
     * @return	The string that is the title for this tab.
     */
    public abstract String getPageTitle();

    /**
     * Notification from Console when page is selected.
     * Called after previously selected page has beeen
     * notified that it is unselected.
     *
     * @param parent	the IFramework parent of this object
     */
    public abstract void pageSelected(IFramework parent);

    /**
     * Notification from Console when page is UN-selected.
     * Called before the to-be selected page has beeen
     * notified that it will be selected.
     *
     * @param parent	the IFramework parent of this object
     */
    public abstract void pageUnselected(IFramework parent);

    /**
     * Notification from Console that the window is closing.
     * (in response to a Close or Exit selection).  In
     * response, a CloseVetoException may be thrown which
     * causes Console to inform the user that there is unsaved
     * data in this tab, and allows the user to abort the
     * close operation.
     *
     * @param parent	the IFramework parent of this object
     * @exception CloseVetoException thrown to veto the close action.
     */
    public abstract void actionViewClosing(IFramework parent)
            throws CloseVetoException;

    /**
     * Makes a copy of this tab.  This method is deprecated
     * because the File->New Window functionality has been removed.
     *
     * @deprecated functionality is no longer needed, method not called.
     */
    @Deprecated
    public abstract Object clone();
}
