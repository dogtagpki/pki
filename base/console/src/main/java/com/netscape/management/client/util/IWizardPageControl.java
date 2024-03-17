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

import javax.swing.JPanel;

/**
 * Defines properties and functionality for a wizard page.
 */
public interface IWizardPageControl {
    /**
      * return the current page in the page wizard
      *
      * @return current selected page
      */
    public abstract JPanel getCurrentPage();

    /**
     * return the next page in the page wizard
     *
     * @return next page
     */
    public abstract JPanel getNextPage();

    /**
     * return the previous page in the page wizard
     *
     * @return previous page
     */
    public abstract JPanel getPrevPage();

    /**
     * call when the state of the page wizard is completed
     */
    public abstract void wizardCompleted();

    /**
     * call when the state of the page wizard is cancelled
     */
    public abstract void wizardCanceled();

    /**
     * call when the help button is invoked
     */
    public abstract void helpInvoked();

    /**
     * set the owner of the page wizard
     *
     * @param wizard page owner
     */
    public abstract void setOwner(IWizardControl wizard);
}
