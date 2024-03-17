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
package com.netscape.management.client.security.csr;


import java.awt.*;
import javax.swing.event.*;

/**
* Specifies the UI for an information request page.
* This page is part of a sequence of steps in Console's 
* Request and Renew Wizards.
*/
public interface IContentPage
{
    /**
    * Retrieves a short name that describes this page.
    * The name is displayed in the title bar of the wizard.
    * Example: "Contact Information" or "Certificate Information"
    * 
    * @return string    name of this page
    */
    public String getPageName();

    /**
    * Retrieves the component that provides the UI for this page.
    * TODO: specify preferred size requirements.
    * 
    * @return Component    name of this page
    */
    public Component getComponent();

    /**
    * 
    */
    public void addChangeListener(ChangeListener l);

    /**
    * 
    */
    public void removeChangeListener(ChangeListener l);

    /**
    * Determines if the field values on this page are acceptable (in range)
    * so that execution flow can proceed to the next page of the Wizard.
    * 
    * @return true if it is OK to display the next page.
    */
    public boolean isPageValidated();
 
    /**
     * Returns the next page in the sequence, or NULL of it does not exist.
     * 
     * @return             object that defines the properties of the specified page
     */
    public IContentPage getNextPage();
    
    /**
     * Returns the previous page in the sequence, or NULL of it does not exist.
     * 
     * @return             object that defines the properties of the specified page
     */
    public IContentPage getPreviousPage();
    
    /**
     * Returns the number of pages remaining in this sequence.
     * The number should be based on the number of selected options.
     * 
     * @return             object that defines the properties of the specified page
     */
    public int getRemainingPageCount();
    
    /**
    * Retrieves the URL representing the help content for this page.
    * This method is typically invoked as a result of the Help button being pressed.
    * 
    * @return URL string
    */
    public String getHelpURL();
}
