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

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.table.*;
import javax.swing.event.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.preferences.*;
import com.netscape.management.client.util.*;

class FontPreferencesTab extends AbstractPreferencesTab {
    public static String PREFERENCES_PROFILE = "FontProfile_";
    public static String PREFERENCE_ActiveFontProfile = "ActiveFontProfile";

    private static ResourceSet resource = new ResourceSet("com.netscape.management.client.default");
    private static boolean isRestartRequired = false;
    private boolean isDirty = false;
    private JComboBox profileCombo;
    private JButton changeButton;
    private JButton saveButton;
    private JButton removeButton;
    private Table fontTable;
    private FontTableModel fontTableModel;
    private Hashtable fontHashtable = new Hashtable();
    private PreferenceManager preferenceManager;
    private ProfileSelectionListener profileSelectionListener = new ProfileSelectionListener();
    private TableSelectionListener fontTableSelectionListener = new TableSelectionListener();
    private boolean isTabCreated = false;

    public static String i18n(String id) {
        return resource.getString("fontTab", id);
    }

    public FontPreferencesTab()
    {
        preferenceManager = PreferenceManager.getPreferenceManager(Framework.IDENTIFIER, Framework.MAJOR_VERSION);
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
        profileCombo = new JComboBox();
        GridBagUtil.constrain(panel, profileCombo, 0, 1, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 1,
                SEPARATED_COMPONENT_SPACE);
        String label = UITools.getDisplayLabel(i18n("profile"));
        JLabel fontProfileLabel = new JLabel(label);
        char mnemonicChar = UITools.getMnemonic(i18n("profile"));
        char upperChar = Character.toUpperCase(mnemonicChar);
        char lowerChar = Character.toLowerCase(mnemonicChar);
        fontProfileLabel.setDisplayedMnemonic(mnemonicChar);
        ProfileListener profileListener = new ProfileListener();
        profileCombo.registerKeyboardAction(profileListener,
            KeyStroke.getKeyStroke(Character.getNumericValue(upperChar),KeyEvent.VK_ALT),
            JComponent.WHEN_IN_FOCUSED_WINDOW);
        profileCombo.registerKeyboardAction(profileListener,
            KeyStroke.getKeyStroke(Character.getNumericValue(lowerChar),KeyEvent.VK_ALT),
            JComponent.WHEN_IN_FOCUSED_WINDOW);
        GridBagUtil.constrain(panel, fontProfileLabel, 0, 0,
                                1, 1, 0.0, 0.0, GridBagConstraints.NORTHWEST,
                                GridBagConstraints.NONE, 0, 0, 0, 0);
        
        saveButton = JButtonFactory.create(i18n("saveas"),
                        new SaveButtonListener(),"SAVE");
        saveButton.setToolTipText(i18n("saveas_tt"));
        GridBagUtil.constrain(panel, saveButton, 1, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.NONE,
                0, 0, 0, COMPONENT_SPACE);

        removeButton = JButtonFactory.create(i18n("remove"),
                          new RemoveButtonListener(),"REMOVE");
        removeButton.setToolTipText(i18n("remove_tt"));
        GridBagUtil.constrain(panel, removeButton, 2, 1, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.NONE, 0, 0, 0, 0);

        fontHashtable = getPreferenceFonts(Framework.PREFERENCES_FONTS);
        fontTableModel = new FontTableModel();
        fontTableModel.addColumn(i18n("columnItem"));
        fontTableModel.addColumn(i18n("columnFont"));
        fontTableModel.setTableData(fontHashtable);
        
        fontTable = new Table(fontTableModel, true);
        fontTable.setToolTipText(i18n("table_tt"));
        fontTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        ListSelectionModel listSelectionModel = fontTable.getSelectionModel();
        listSelectionModel.addListSelectionListener(fontTableSelectionListener);
        JScrollPane sp = new JScrollPane(fontTable);
        GridBagUtil.constrain(panel,
                sp, 0, 2, 3, 1,
                1.0, 1.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.BOTH, SEPARATED_COMPONENT_SPACE, 0,
                0, 0);

        changeButton = JButtonFactory.create(i18n("change"),
                          new ChangeButtonListener(),"CHANGE");
        changeButton.setToolTipText(i18n("change_tt"));
        changeButton.setEnabled(fontTable.getSelectedRowCount() > 0);
        fontTable.addMouseListener(new ExtendedMouseAdapter(changeButton));
        GridBagUtil.constrain(panel, changeButton, 0, 3, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.NONE, COMPONENT_SPACE, 0, 0, 0);
        reloadProfiles();
        Preferences p = preferenceManager.getPreferences(
                Framework.PREFERENCES_GENERAL);
        String group = p.getString(PREFERENCE_ActiveFontProfile);
        profileCombo.setSelectedItem(group);
        JButtonFactory.resize(saveButton, removeButton);
        profileCombo.addActionListener(profileSelectionListener);
        return panel;
    }
    
    class FontTableModel extends DefaultTableModel
    {
        public boolean isCellEditable(int row, int column)
        {
            return false;
        }
        
        public void setTableData(Hashtable ht)
        {
            int rowCount = fontTableModel.getRowCount();
            for(int i = rowCount-1; i >= 0; i--)
                fontTableModel.removeRow(i);
    
            Enumeration e = ht.keys();
            while (e.hasMoreElements()) 
            {
                String fontID = (String) e.nextElement();
                JLabel label = new JLabel(FontPreferencesTab.i18n("sampleText"));
                label.setFont((Font)fontHashtable.get(fontID));
                fontTableModel.addRow(new Object[] { FontFactory.getFontDescription(fontID), label });
            }
        }
    }

    public void okInvoked() {
        if (isDirty) {
            saveFontTable(Framework.PREFERENCES_FONTS, false);
            Preferences p = preferenceManager.getPreferences(
                    Framework.PREFERENCES_GENERAL);
            String name = (String)profileCombo.getSelectedItem();
            if (name != null && name.length() > 0) {
                p.set(PREFERENCE_ActiveFontProfile, name);
                saveFontTable(PREFERENCES_PROFILE + name, true);
            }
        }
    }

    /**
     * Called when the Help button is pressed.
     */
    public void helpInvoked()
    {
        ConsoleHelp.showContextHelp("preferences-fonts");
    }

    /**
     * Sets whether the changes made in this tab require
     * Console to be restarted in order to be effective.
     * This method preserves the state across multiple 
     * invocations of this class.  It then calls
     * AbstractDialog.setRestartRequired.
     */
    private void requireRestart()
    {
        isRestartRequired = true;
        setRestartRequired(isRestartRequired);
    }
    
    
    class TableSelectionListener implements ListSelectionListener {
        public void valueChanged(ListSelectionEvent e) {
            changeButton.setEnabled(fontTable.getSelectedRowCount() > 0);
        }
    }

    class ProfileSelectionListener implements ActionListener {
        public void actionPerformed(ActionEvent event) {
            String group = (String)profileCombo.getSelectedItem();
            fontHashtable = getPreferenceFonts(PREFERENCES_PROFILE + group);
            fontTableModel.setTableData(fontHashtable);
            removeButton.setEnabled(true);
            isDirty = true;
            requireRestart();
        }
    }

    class ChangeButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent event) {
            TableModel model = fontTable.getModel();
            int row[] = fontTable.getSelectedRows();
            JLabel label = (JLabel) model.getValueAt(row[0], 1);
            Font f = label.getFont();
            FontChooserDialog d = new FontChooserDialog(FontPreferencesTab.this.getFrame(), f.getName(), f.getStyle(), f.getSize());
            d.show();
            if (!d.isCancel()) {
                for (int i = 0; i < row.length; i++) {
                    label = (JLabel) model.getValueAt(row[i], 1);
                    label.setFont(new Font(d.getFontName(), d.getFontStyle(), d.getFontSize()));
                    String description1 = (String) model.getValueAt(row[i], 0);
                    for (Enumeration e = fontHashtable.keys();
                            e.hasMoreElements();) {
                        String fontID = (String) e.nextElement();
                        String description2 =FontFactory.getFontDescription(fontID);
                        if (description1.equals(description2))
                            fontHashtable.put(fontID, label.getFont());
                    }
                }
                profileCombo.removeActionListener(profileSelectionListener);
                profileCombo.addActionListener(profileSelectionListener);
                fontTable.validate();
                fontTable.repaint();
                isDirty = true;
                requireRestart();
            }
        }
    }

    class SaveButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            NewProfile d = new NewProfile(FontPreferencesTab.this.getFrame());
            d.show();
            if (!d.isCancel()) {
                String name = d.getResult();
                saveFontTable(PREFERENCES_PROFILE + name, true);
                profileCombo.removeActionListener(profileSelectionListener);
                reloadProfiles();
                profileCombo.setSelectedItem(name);
                profileCombo.addActionListener(profileSelectionListener);
                isDirty = true;
                requireRestart();
            }
        }
    }

    class RemoveButtonListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            String name = (String)profileCombo.getSelectedItem();
            int value = JOptionPane.showConfirmDialog(FontPreferencesTab.this.getFrame(),
                    i18n("removeConfirm") + name + "?",
                    i18n("removeConfirmTitle"), JOptionPane.YES_NO_OPTION,
                    JOptionPane.QUESTION_MESSAGE);
            if (value == JOptionPane.YES_OPTION) {
                Preferences p = preferenceManager.getPreferences(
                        PREFERENCES_PROFILE + name);
                p.delete();
                profileCombo.removeActionListener(
                        profileSelectionListener);
                reloadProfiles();
                profileCombo.addActionListener(profileSelectionListener);
            }
        }
    }
    
    class ProfileListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            profileCombo.requestFocus();
        }
    }
    
    private void saveFontTable(String group, boolean needToSave) {
        Preferences p = preferenceManager.getPreferences(group);
        Enumeration e = fontHashtable.keys();
        while (e.hasMoreElements()) {
            String key = (String) e.nextElement();
            p.set(key, FontFactory.toFontInfoString((Font)fontHashtable.get(key)));
        }
        if (needToSave)
            p.save();
    }

    private Hashtable getPreferenceFonts(String group) 
    {
        Hashtable ht = new Hashtable();
        Preferences p = preferenceManager.getPreferences(group);
        if (!p.isEmpty()) 
        {
            Enumeration e = p.getNames();
            while (e.hasMoreElements()) 
            {
                String key = (String) e.nextElement();
                String fontInfo = (String) p.get(key);
                ht.put(key, FontFactory.toFont(fontInfo));
            }
            return ht;
        }

        // load default fonts
        Enumeration e = FontFactory.getFontIDs();
        while(e.hasMoreElements())
        {
            String screenElement = (String) e.nextElement();
            ht.put(screenElement, FontFactory.getFont(screenElement));
        }
        return ht;
    }

    void reloadProfiles() {
        String groups[] = preferenceManager.getPreferencesList();
        profileCombo.removeAllItems();
        profileCombo.setEnabled(true);
        removeButton.setEnabled(true);
        if (groups != null) {
            profileCombo.removeAllItems();
            for (int i = 0; i < groups.length; i++) {
                if (groups[i].indexOf(PREFERENCES_PROFILE) != -1) {
                    int startIndex =
                            groups[i].indexOf(PREFERENCES_PROFILE) +
                            PREFERENCES_PROFILE.length();
                    String s = groups[i].substring(startIndex);
                    profileCombo.addItem(s);
                }
            }
        }

        if (profileCombo.getItemCount() == 0) {
            profileCombo.addItem(" ");
            profileCombo.setEnabled(false);
            removeButton.setEnabled(false);
        }
    }

    // TODO: move to util
    public static String getUID() {
        return String.valueOf(System.currentTimeMillis());
    }
}

class NewProfile extends GenericDialog implements UIConstants
{
    JTextField textField = new JTextField(22);

    public NewProfile(JFrame frame) {
        super(frame, FontPreferencesTab.i18n("saveTitle"), OK | CANCEL | HELP, HORIZONTAL);
        getContentPane().add(createTabPanel());
        setFocusComponent(textField);
        enableOK();
        EventListener l = new ChangeEventListener();
        textField.getDocument().addDocumentListener((DocumentListener) l);
    }

    protected JPanel createTabPanel() {
        JPanel panel = new JPanel();

        GridBagLayout gridbag = new GridBagLayout();
        panel.setLayout(gridbag);
        GridBagConstraints c = new GridBagConstraints();

        JLabel viewLabel = new JLabel(FontPreferencesTab.i18n("saveText"));
        viewLabel.setLabelFor(textField);
        GridBagUtil.constrain(panel, viewLabel, 0, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(panel, textField, 0, 1, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTHWEST,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);
        return panel;
    }

    public void helpInvoked() {
        ConsoleHelp.showContextHelp("preferences-NewProfileDialog");
    }

    public String getResult() {
        return textField.getText();
    }

    private void enableOK() {
        String s = textField.getText().trim();
        boolean enable = (s.length() > 0);
        setOKButtonEnabled(enable);
    }

    class ChangeEventListener implements DocumentListener {
        public void insertUpdate(DocumentEvent e) {
            enableOK();
        }

        public void removeUpdate(DocumentEvent e) {
            enableOK();
        }

        public void changedUpdate(DocumentEvent e) {
            enableOK();
        }
    }
}
