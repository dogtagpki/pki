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
package com.netscape.management.client.ace;

import javax.swing.*;
import netscape.ldap.LDAPConnection;

/**
 * Defines properties and functionality for a tab
 * that appears in the Access Control Editor (ACIEditor) dialog.
 *
 * @author Andy Hakim
 */
public interface IACITab 
{
    /**
     * Called once to provide global information about 
     * this session of the ACIEditor.
     * 
     * @param parentFrame   a JFrame object that will be the parent for this dialog.
     * @param aciLdc        a LDAP connection to server where ACIs reside
     * @param aciDN         a DN where ACIs reside
     * @param ugLdc         a LDAP connection to server where UGs reside
     * @param ugDN          a DN where Users and Groups reside
     */
    public abstract void initialize(JFrame parentFrame, LDAPConnection aciLdc, String aciDN, LDAPConnection ugLdc, String ugDN);
    
    /**
     * Retrieves the title for this tab.
     * The title should be short, usually one word.
     * 
     * @return the title string for this tab.
     */
    public abstract String getTitle();

    /**
     * Retrieves the Component which renders the
     * content for this tab.
     */
    public abstract JComponent getComponent();
    
    /**
     * Indicates the preferred tab position in the tabbed pane.
     * Range: 0 to 10 or -1 for LAST.
     * If multiple tabs have the same preferred position,
     * the tabs are ordered by name.
     * 
     * @return the preferred tab position in the tabbed pane
     */
    public abstract int getPreferredPosition();
    
    /**
     * Returns a list of supported ACI attributes (keywords, operators, values).
     * This information is used when editing manually for the purposes of
     * syntax checking, color highlighting, and word completion.
     * 
     * Alphanumeric and digit characters are treated as required literals.
     * Special characters:
     * "|" used to indicate multiple choices
     * "*" used to indicate zero or more characters
     */
    public abstract ACIAttribute[] getSupportedAttributes();
    
    /**
     * Notification that the ACI has changed
     * This method is called in two situations:
     * 1) during initialization, after getComponent is called.
     * 2) after a change from manual to visual mode.
     * 
     * The tab implementation should examine the changed aci and return
     * all parsed ACIAttribute objects the tab recognized and processed.
     * The return value may be null if no attributes were recognized.
     * 
     * @param aciAttributes  the aci as an array of ACIAttribute objects
     * @param aciString      the raw, unaltered aci string
     * @return an array of ACIAttribute objects that were recognized
     * @exception Exception occurred while processing recognized ACIAttributes
     * 
     * @see ACIParser#parseACI
     * @see ACIAttribute
     */
    public abstract ACIAttribute[] aciChanged(ACIAttribute[] aciAttributes, String aciString) throws Exception;
    
    /**
     * Returns a new ACI that includes attributes from this tab.
     * This tab's attributes can be appended/prepended/inserted 
     * into the existingACI.
     * 
     * This method is called when in two situations:
     * 1) when the user presses OK in the ACIEditor dialog.
     * 2) after a change from visual to manual mode.
     * 
     * @param existingACI   the existing aci
     * @return the new aci that includes this tab's attributes
     */
    public abstract StringBuffer createACI(StringBuffer existingACI);

    /**
     * Notification that this tab has been selected.
     */
    public abstract void tabSelected();
        
    /**
     * Notification that the Help button has been pressed.
     */
    public abstract void helpInvoked();

    /**
     * Notification that the Help button has been pressed.
     */
    public abstract void okInvoked();

    /**
     * Notification that the Help button has been pressed.
     */
    public abstract void cancelInvoked();
}
