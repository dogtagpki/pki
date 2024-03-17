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

import java.awt.Component;
import javax.swing.event.ChangeListener;


/**
* Specifies the UI for an information request page.
* This page is part of a sequence of steps in Console's 
* Request and Renew Wizards.
*/
public interface IUIPage
{
    /**
     * Retrieves a short name that describes this page.
     * The name is displayed in the title bar of the wizard.
     * Example: "Contact Information" or "Submission Status"
     * 
     * @I18N: String displayed in UI -- should be localized 
     * @return string    name of this page
     */
    public String getPageName();

    /**
     * Retrieves the UI component for this page.
     * TODO: specify preferred size requirements.
     * TODO: change this to JComponent?
     * 
     * @return Component object that defines this page.
     */
    public Component getComponent();

    /**
     * Registers listener so that it will receive ChangeListener events 
     * when any fields in this page change their state. 
     * 
     * @param listener    ChangeListener object to be added to the   
     *                    internal list of listeners for this page. 
     */
    public void addChangeListener(ChangeListener listener);

    /**
     * Unregisters listener so that it will no longer receive ChangeListener events 
     * 
     * @param listener    ChangeListener object to be removed to the   
     *                    internal list of listeners for this page. 
     */
    public void removeChangeListener(ChangeListener listener);

    /**
     * Determines if the field values on this page are acceptable 
     * so that execution can proceed to the next page of the Wizard.
     * This method is called whenever the page changes, as triggered 
     * through a ChangeListener event. 
     * 
     * @return true if it is OK to move to the next page.
     */
    public boolean isPageValidated();

    /**
     * Retrieves the next page in the sequence, or NULL if no more pages exist.
     * 
     * @return    IUIPage object containing the UI content
     */
    public IUIPage getNextPage();
    
    /**
     * Retrieves the previous page in the sequence, or NULL if no more pages exist.
     * 
     * @return    IUIPage object containing the UI content
     */
    public IUIPage getPreviousPage();
    
    /**
     * Retrieves the number of pages remaining in this wizard sequence.
     * The number represents only the wizard pages that will be 
     * provided by this plugin, not pages provided by Console.
     * The number should be based on the currently selected options.
     * This method is called whenever the page changes, as triggered 
     * through a ChangeListener event. 
     * 
     * @return    count of remaining plugin pages
     */
    public int getRemainingPageCount();
    
    /**
     * Retrieves the URL representing the help content for this UI page.
     * This method is called when the Help button is pressed.
     * TODO: guidelines for authoring help 
     * 
     * @return    URL string
     */
    public String getHelpURL();
}
