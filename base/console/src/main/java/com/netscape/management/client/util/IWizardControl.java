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

package com.netscape.management.client.util;

/**
 * Defines properties and functionality for a generic Wizard dialog.
 */
public interface IWizardControl {
    /**
      * enable/disable the go forward button
      *
      * @param enabled turn on/off the go forward button
      */
    public abstract void setCanGoForward(boolean enabled);

    /**
     * enable/disable the go backward button
     *
     * @param enabled turn on/off the go backward button
     */
    public abstract void setCanGoBackword(boolean enabled);

    /**
     * set whether the page is last page or not
     *
     * @param lasPage true if the current page is last page
     */
    public abstract void setIsLastPage(boolean lastPag);

    /**
     * the next button is selected
     *
     */
    public abstract void nextInvoked();

    /**
     * the back button is selected
     *
     */
    public abstract void backInvoked();

    /**
     * the cancel button is selected
     */
    public abstract void cancelInvoked();
}
