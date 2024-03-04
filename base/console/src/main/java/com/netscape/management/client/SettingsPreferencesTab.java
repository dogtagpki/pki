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

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.preferences.*;
import com.netscape.management.client.console.*;

class SettingsPreferencesTab extends AbstractPreferencesTab {
    private static ResourceSet resource = new ResourceSet("com.netscape.management.client.default");
    private static ResourceSet helpResource = new ResourceSet("com.netscape.management.client.help");
    private JButton clearButton;
    private JRadioButton storeDirectoryRadio;
    private JRadioButton storeDiskRadio;
    private static boolean isRestartRequired = false;
    private boolean clearPressed = false;
    private boolean isTabCreated = false;

    private static String i18n(String id) {
        return resource.getString("settingsTab", id);
    }

    public SettingsPreferencesTab()
    {
        setTitle(i18n("title"));
    }

    /**
     * Called once to provide global information about 
     * this session of the Preferences dialog.
     * 
     * @param parentFrame   a JFrame object that will be the parent for this dialog.
     */
    public void initialize(JFrame parentFrame)
    {
        super.initialize(parentFrame);
        isTabCreated = false;
    }
    
    /**
     * Called when this tab is selected.
     * Sets the component first time tab is selected.
     */
    public void tabSelected()
    {
        if(!isTabCreated)
        {
            isTabCreated = true;
            setRestartRequired(isRestartRequired);
            setComponent(createTabPanel());
        }
    }
    
    protected JPanel createTabPanel() {
        JPanel panel = new JPanel();
        panel.setLayout(new GridBagLayout());

        boolean canSetLocalPreferencesFlag =
                Console.canSetLocalPreferencesFlag();
        boolean localPreferencesFlag = Console.getLocalPreferencesFlag();
        ButtonGroup radioGroup = new ButtonGroup();
        JPanel radioPanel = new JPanel();
        radioPanel.setLayout(new GridBagLayout());
        radioPanel.setBorder(BorderFactory.createTitledBorder(i18n("where")));
        radioPanel.setEnabled(canSetLocalPreferencesFlag);
        GridBagUtil.constrain(panel, radioPanel, 0, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        storeDirectoryRadio = new JRadioButton(UITools.getDisplayLabel(i18n("remote")));
        storeDirectoryRadio.setSelected(!localPreferencesFlag);
        storeDirectoryRadio.setEnabled(canSetLocalPreferencesFlag);
        radioGroup.add(storeDirectoryRadio);
        GridBagUtil.constrain(radioPanel, storeDirectoryRadio, 0, 0,
                1, 1, 1.0, 0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, COMPONENT_SPACE, 0,
                COMPONENT_SPACE);

        storeDiskRadio = new JRadioButton(UITools.getDisplayLabel(i18n("local")));
        storeDiskRadio.setSelected(localPreferencesFlag);
        storeDiskRadio.setEnabled(canSetLocalPreferencesFlag);
        radioGroup.add(storeDiskRadio);
        GridBagUtil.constrain(radioPanel, storeDiskRadio, 0, 1, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE);

        
        // -------------------------------------------------------------------- //
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridBagLayout());
        GridBagUtil.constrain(panel, buttonPanel, 0, 2, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        clearButton = JButtonFactory.create(i18n("reset"),new ClearButtonListener(),"RESET");
        clearButton.setToolTipText(i18n("resetDescription"));
        GridBagUtil.constrain(buttonPanel, clearButton, 0, 0, 1, 1,
                0.0, 0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.NONE, 0, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE);

        GridBagUtil.constrain(buttonPanel,
                new JLabel(i18n("resetDescription")), 1, 0, 1, 1, 1.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.NONE,
                0, COMPONENT_SPACE, COMPONENT_SPACE, COMPONENT_SPACE);

        // -------------------------------------------------------------------- //
        GridBagUtil.constrain(panel, new JPanel(), 0, 3, 1, 1, 1.0,
                1.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.BOTH, 0, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE);
        return panel;
    }

    /**
     * Called when the OK or Close button is pressed.
     */
    public void okInvoked() {
        boolean storeLocalState = Console.getLocalPreferencesFlag();
        Console.setLocalPreferencesFlag(
                !storeDirectoryRadio.isSelected());
        PreferenceManager pm = PreferenceManager.getPreferenceManager(
                Framework.IDENTIFIER, Framework.MAJOR_VERSION);
        Preferences p = pm.getPreferences(Framework.PREFERENCES_GENERAL);
   
        if (storeLocalState != storeDiskRadio.isSelected()) {
            if (storeDiskRadio.isSelected()) {
                copyPreferences(pm,
                        new FilePreferenceManager(
                        Framework.IDENTIFIER, Framework.MAJOR_VERSION));
            } else {
                ConsoleInfo ci = Console.getConsoleInfo();
                PreferenceManager toMgr = new LDAPPreferenceManager(
                        ci.getLDAPConnection(), ci.getUserPreferenceDN(),
                        Framework.IDENTIFIER, Framework.MAJOR_VERSION);
                copyPreferences(pm, toMgr);
            }
        }
        
        if(clearPressed)
        {
            PreferenceManager.clearAllPreferences();
            isRestartRequired = true;
        }
    }

    /**
     * Called when the Help button is pressed.
     */
    public void helpInvoked()
    {
        ConsoleHelp.showContextHelp("preferences-settings");
    }

    class ClearButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            setRestartRequired(true);
            clearPressed = true;
        }
    }

    
    
    /**
      * Copy all stored preferences from one manager to another.
      * Used to transfer preferences from file to ldap and vice-versa.
      */
    public void copyPreferences(PreferenceManager fromMgr,
            PreferenceManager toMgr) {
        String groups[] = fromMgr.getPreferencesList();
        if (groups != null) {
            for (int i = 0; i < groups.length; i++) {
                String group = groups[i];
                if (!group.equals("Login"))// Login group is disk only
                {
                    Preferences toPrefs = toMgr.getPreferences(group);
                    Preferences fromPrefs = fromMgr.getPreferences(group);
                    Enumeration e = fromPrefs.getNames();
                    while (e.hasMoreElements()) {
                        Object name = e.nextElement();
                        Object value = fromPrefs.get(name);
                        toPrefs.set((String) name, (String) value);
                    }
                }
            }
            toMgr.savePreferences();
        }
    }
}
