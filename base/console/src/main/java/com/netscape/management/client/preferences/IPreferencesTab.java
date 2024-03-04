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
package com.netscape.management.client.preferences;


import javax.swing.*;
import javax.swing.event.*;

/**
 * Defines properties and functionality for a tab that appears in the 
 * Console preferences dialog.
 *
 * @author Andy Hakim
 */
public interface IPreferencesTab 
{
    /**
     * Called once to provide global information about 
     * this session of the ACIEditor.
     * 
     * @param parentFrame   a JFrame object that will be the parent for this dialog.
     */
    public abstract void initialize(JFrame parentFrame);
    
    /**
     * Retrieves the Component which renders the content for this tab.
     */
    public abstract JComponent getComponent();

    /**
     * Retrieves the text that appears on this tab.
     * The title should be a concise, one word string.
     * 
     * @return the localized string for this tab.
     */
    public abstract String getTitle();

    /**
     * Called when this tab is selected.
     */
    public abstract void tabSelected();

    /**
     * Called when the Help button is pressed.
     * @see com.netscape.management.client.util.Help
     */
    public abstract void helpInvoked();

    /**
     * Called when the OK or Close button is pressed.
     */
    public abstract void okInvoked();

    /**
     * Called when the Cancel button is pressed.
     * 
     * @see #cancelInvoked
     */
    public abstract void cancelInvoked();
    
    /**
     * Determines if the changes made in this tab can
     * be cancelled.  In some cases, changes made in
     * a tab are permanent, and Cancel is not possible.
     * In those cases, this tab should return false;
     * 
     * If the return value is false, the Preferences
     * dialog hides the Cancel button and changes the
     * text of the OK button to Close.
     * 
     * @return false if changes made in this tab cannot be changed.
     */
    public abstract boolean isCancelEnabled();
    
    /**
     * Registers listener so that it will receive ChangeListener events 
     * when any fields in this page change their state. 
     * 
     * @param l    ChangeListener object to be added to the   
     *             internal list of listeners for this page. 
     */
    public abstract void addChangeListener(ChangeListener l);

    /**
     * Unregisters listener so that it will no longer receive ChangeListener events 
     * 
     * @param l    ChangeListener object to be removed to the   
     *             internal list of listeners for this page. 
     */
    public abstract void removeChangeListener(ChangeListener l);
}
