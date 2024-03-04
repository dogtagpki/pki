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

import java.awt.*;
import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.util.*;

/**
 * An abstract implementation of IPreferencesTab.
 * The methods that requires implementation are:
 * getComponent(), okInvoked(), and helpInvoked().
 *
 * @see IPreferencesTab
 * @author Andy Hakim
 */
public abstract class AbstractPreferencesTab implements IPreferencesTab, UIConstants
{
    private static ImageIcon warningIcon = new RemoteImage("com/netscape/management/client/images/warn16.gif");
    private String title = "TODO: setTitle";
    private JComponent tabComponent = null;
    private JComponent restartComponent = null;
    private Vector changeListeners = null;
    private boolean isCancelEnabled = true;
    private boolean isRestartRequired = true;
    private JFrame parentFrame = null;
    
    /**
     * The recommended initial width for preference tabs.
     */
    protected static int DEFAULT_WIDTH = 350;

    /**
     * The recommended initial height for preference tabs.
     */
    protected static int DEFAULT_HEIGHT = 280;

    /**
     * Called once to provide global information about 
     * this session of the ACIEditor.
     * 
     * @param parentFrame   a JFrame object that will be the parent for this dialog.
     */
    public void initialize(JFrame parentFrame)
    {
        this.parentFrame = parentFrame;
		this.tabComponent = null;
    }
    
    /**
     * Returns the parent frame received in initialize.
     * 
     * @see #initialize
     */
    protected JFrame getFrame()
    {
        return parentFrame;
    }
    
    /**
     * Retrieves the text that appears on this tab.
     * The title should be a concise, one word string.
     * 
     * @return the localized string for this tab.
     */
    public String getTitle()
    {
        return title;
    }

    /**
     * Sets the title for this tab.
     * 
     * @param title     the title string
     */
    public void setTitle(String title)
    {
        this.title = title;
    }
    

    /**
     * Retrieves the Component which renders the content for this tab.  
     * The default implementation returns an empty panel.
     */
    public JComponent getComponent()
    {
		if(tabComponent == null)
			tabComponent = createTabComponent();
        return tabComponent; 
    }

    /**
     * Creates a panel with standard size and borders and
     * a "restart required" warning label that is 
     * conditionally displayed at the bottom.
     * 
     * @see #setRestartRequired
     */
    private JComponent createTabComponent()
    {
        JPanel p = new JPanel();
        GridBagLayout gbl = new GridBagLayout();
        p.setLayout(gbl);        
        GridBagConstraints gbc = new GridBagConstraints();
        p.setBorder(BorderFactory.createEmptyBorder(VERT_WINDOW_INSET, HORIZ_WINDOW_INSET, VERT_WINDOW_INSET, HORIZ_WINDOW_INSET));

		restartComponent = new JLabel(PreferencesDialog.i18n("restart"), warningIcon, SwingConstants.LEFT);
        restartComponent.setMinimumSize(restartComponent.getPreferredSize());
        restartComponent.setVisible(isRestartRequired);
        gbc.gridx = 0;       gbc.gridy = 1;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(COMPONENT_SPACE, 0, 0, 0);
        gbl.setConstraints(restartComponent, gbc);
        p.add(restartComponent);
        
        int width = DEFAULT_WIDTH + HORIZ_WINDOW_INSET * 2;
        int height = DEFAULT_HEIGHT + VERT_WINDOW_INSET * 2;
        p.setPreferredSize(new Dimension(width, height));
		return p;
    }

    /**
     * Sets a component inside a panel with a standard
     * size and border and a "restart required" warning 
     * label that is conditionally displayed at the bottom.
     * 
     * @see #setRestartRequired
     */
    public void setComponent(JComponent c)
    {
		if(tabComponent == null)
			tabComponent = createTabComponent();

        GridBagLayout gbl = (GridBagLayout)tabComponent.getLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        
        gbc.gridx = 0;       gbc.gridy = 0;
        gbc.gridwidth = 1;   gbc.gridheight = 1;
        gbc.weightx = 1.0;   gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbl.setConstraints(c, gbc);
        tabComponent.add(c);
    }

    /**
     * Determines if the changes made in this tab require
     * Console to be restarted in order to be effective.
     * 
     * @return true if restart Console is required.
     * @see #setRestartRequired
     */
    public boolean isRestartRequired()
    {
        return isRestartRequired;
    }
    
    /**
     * Sets whether the changes made in this tab require
     * Console to be restarted in order to be effective.
     * If the parameter value is true, this tab will display
     * an appropriate warning message below the tab contents.
     * Sample warning message:
     * "Changes will not go into effect until you restart Console."
     * 
     * @return true if restart Console is required.
     */
    public void setRestartRequired(boolean state)
    {
        isRestartRequired = state;
        if(restartComponent != null)
            restartComponent.setVisible(isRestartRequired);
    }
    
    
    /**
     * Called when this tab is selected.
     * Default implementation does nothing.
     */
    public void tabSelected()
    {
    }

    /**
     * Called when the Help button is pressed.
     */
    public abstract void helpInvoked();

    /**
     * Called when the OK or Close button is pressed.
     */
    public void okInvoked()
	{
	}

	/**
     * Called when the cancel button is pressed.
     * Default implementation does nothing.
     */
    public void cancelInvoked()
    {
    }

    /**
     * Registers listener so that it will receive ChangeListener events 
     * when any fields in this page change their state. 
     * 
     * @param listener    ChangeListener object to be added to the   
     *                    internal list of listeners for this page. 
     */
    public void addChangeListener(ChangeListener l)
    {
        if(changeListeners == null)
            changeListeners = new Vector();
        changeListeners.addElement(l);
    }

    /**
     * Unregisters listener so that it will no longer receive ChangeListener events 
     * 
     * @param listener    ChangeListener object to be removed to the   
     *                    internal list of listeners for this page. 
     */
    public void removeChangeListener(ChangeListener l)
    {
        if(changeListeners != null)
            changeListeners.removeElement(l);
    }

    /**
     * Determines if the changes made in this tab can
     * be cancelled.  In some cases, changes made in
     * a tab are permanent, and Cancel is not possible.
     * If the return value is false, the Preferences
     * dialog hides the Cancel button and changes the
     * text of the OK button to Close.
     * 
     * @return false if changes made in this tab cannot be changed.
     */
    public boolean isCancelEnabled()
    {
        return isCancelEnabled;
    }

    /**
     * Sets the new Cancel state.
     * Fires state change notification to all listeners.
     * 
     * @see fireStateChanged
     */
    public void setCancelEnabled(boolean state)
    {
        isCancelEnabled = state;
        fireStateChanged();
    }
    
    /**
     * Notify all listeners that one or more properties 
     * of this tab have changed.  For example, if the
     * cancel button is no longer valid these listeners
     * are triggered.
     * 
     */
    public void fireStateChanged()
    {
        if(changeListeners != null)
        {
            Enumeration e = changeListeners.elements();
            while(e.hasMoreElements())
            {
                ChangeListener l = (ChangeListener)e.nextElement();
                l.stateChanged(new ChangeEvent(this));
            }
        }
    }
    
}
