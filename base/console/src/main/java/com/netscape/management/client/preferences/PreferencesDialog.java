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

import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.util.*;

/**
 * Displays a dialog to allow users to view and set
 * various preferences in Console.  This dialog is
 * a shell that contains one or more IPreferencesTab
 * obects which show different preference settings.
 *
 * @see IPreferencesTab
 */
public class PreferencesDialog extends GenericDialog
{
    private static ResourceSet resource = new ResourceSet("com.netscape.management.client.preferences.preferences");
    private JFrame parentFrame = null;
    private Vector tabsVector = new Vector();
    private JTabbedPane tabbedPane = null;
	private ChangeListener tabChangeListener = null;

    static String i18n(String id) 
    {
        return resource.getString("dialog", id);
    }

    /**
     * To be used by Console only.
     * Not intended to be public, but necessary due to Java package access rules.
     */
    public PreferencesDialog(JFrame f, IPreferencesTab[] tabs) 
    {
        super(f, i18n("title"), OK | CANCEL | HELP, HORIZONTAL);
        parentFrame = f;
        tabbedPane = createDialogPanel(tabs);
        getContentPane().add(tabbedPane);
        setMinimumSize(getPreferredSize());
    }

    private JTabbedPane createDialogPanel(IPreferencesTab[] tabs) {
        JTabbedPane tabbedPane = new JTabbedPane();
        for(int i = 0; i < tabs.length; i++)
        {
            tabs[i].initialize(parentFrame);
            tabbedPane.addTab(tabs[i].getTitle(),tabs[i].getComponent());
			tabsVector.addElement(tabs[i]);
        }
		tabChangeListener = new ChangeListener()
			{
				public void stateChanged(ChangeEvent e)
				{
					JTabbedPane tp = (JTabbedPane)e.getSource();
					int index = tp.getSelectedIndex();
                    IPreferencesTab tab = (IPreferencesTab)tabsVector.elementAt(index);
					tab.tabSelected();
				}
			};
		tabbedPane.addChangeListener(tabChangeListener);
		tabs[0].tabSelected();
        return tabbedPane;
    }

    protected void okInvoked() {
        Enumeration e = tabsVector.elements();
		
        while(e.hasMoreElements())
        {
            IPreferencesTab tab = (IPreferencesTab)e.nextElement();
            tab.okInvoked();
        }
		tabbedPane.removeChangeListener(tabChangeListener);
        super.okInvoked();
    }

    protected void cancelInvoked() {
        Enumeration e = tabsVector.elements();
		
        while(e.hasMoreElements())
        {
            IPreferencesTab tab = (IPreferencesTab)e.nextElement();
            tab.cancelInvoked();
        }
		tabbedPane.removeChangeListener(tabChangeListener);
        super.cancelInvoked();
    }

    protected void helpInvoked() {
        int i = tabbedPane.getSelectedIndex();
        if (i >= 0)
            ((IPreferencesTab)tabsVector.elementAt(i)).helpInvoked();
    }
}
