// --- BEGIN COPYRIGHT BLOCK ---
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// (C) 2007 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---
package com.netscape.admin.certsrv;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.border.*;
import javax.swing.text.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import java.util.*;
import java.awt.*;
import java.awt.event.*;

/**
 * Netscape Certificate Server 4.0 Default Base Panel
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class CMSBasePanel extends JPanel
    implements  ActionListener, DocumentListener,
                ItemListener, ListSelectionListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    public static Insets DEFAULT_CENTER_INSETS = new Insets(0,0,0,0);
    public static Insets EMPTY_INSETS = new Insets(0,0,0,0);
    public static final int COMPONENT_SPACE = SuiLookAndFeel.COMPONENT_SPACE;
    public static final int SEPARATED_COMPONENT_SPACE =
                                    SuiLookAndFeel.SEPARATED_COMPONENT_SPACE;
    public static final int DIFFERENT_COMPONENT_SPACE =
                                    SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE;

    protected static final int WARNING_MESSAGE = JOptionPane.WARNING_MESSAGE;
    protected static final int ERROR_MESSAGE = JOptionPane.ERROR_MESSAGE;
    protected static final int INFORMATION_MESSAGE = JOptionPane.INFORMATION_MESSAGE;

    protected String mPanelName;            // panel name (UPPERCASE IDENTIFIER)
    protected ResourceBundle mResource;     // resource boundle
    public static int mNonWaitCursor = -1;
    public static Cursor mCursor = null;
    protected JDialog mParent;
    protected JFrame mAdminFrame;

	/*==========================================================
     * constructors
     *==========================================================*/
    public CMSBasePanel(String panelName) {
        this(panelName, ResourceBundle.getBundle(CMSAdminResources.class.getName()));
    }

    public CMSBasePanel(String panelName, ResourceBundle rb) {
        super();
        mPanelName = panelName;
        mResource = rb;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

	/**
	 * Set Panel name
	 * @param name panel name
	 */
    public void setPanelName(String name) {
        mPanelName = name;
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
    }

    //== DocumentListener ==
    public void insertUpdate(DocumentEvent e) {
    }

    public void removeUpdate(DocumentEvent e){
    }

    public void changedUpdate(DocumentEvent e){
    }

    //== ItemListener ==
    public void itemStateChanged(ItemEvent e){
    }

    //== ListSelectionListener ==
    public void valueChanged(ListSelectionEvent e){
    }

    /*==========================================================
	 * protected methods
     *==========================================================*/

    //create string using formated resource string
    //the string format
    protected String getLocalizedString(String keyword, Object param) {
        return CMSAdminUtil.getLocalizedString(mResource, keyword, param);
    }

    protected String getLocalizedString(String keyword, Object [] params) {
        return CMSAdminUtil.getLocalizedString(mResource, keyword, params);
    }


    //=== DIALOG MESSAGE =====================

    protected void showMessageDialog(String keyword, int messageType ) {
        CMSAdminUtil.showMessageDialog(mResource, mPanelName, keyword, messageType);
    }

    protected void showMessageDialog(String keyword) {
        showMessageDialog(keyword, ERROR_MESSAGE);
    }

    protected int showConfirmDialog(String keyword, int messageType ) {
        return CMSAdminUtil.showConfirmDialog(mResource, mPanelName, keyword, messageType);
    }

    protected int showConfirmDialog(String keyword, String[] params, int messageType ) {
        return CMSAdminUtil.showConfirmDialog(mResource, mPanelName, keyword, params, messageType);
    }

    protected int showConfirmDialog(String keyword) {
        return showConfirmDialog(keyword, WARNING_MESSAGE);
    }

    protected int showConfirmDialog(String keyword, String[] params) {
        return showConfirmDialog(keyword, params, WARNING_MESSAGE);
    }

    /**
     * Display Error Message dialog
     *
     * @param message - message to be displayed
     */
    protected void showErrorDialog(String message) {
        CMSAdminUtil.showErrorDialog(mResource, message, ERROR_MESSAGE);
    }

    //=== TITLED BORDER ======================
    protected Border makeTitledBorder(String keyword) {
        String label;
        try {
            label = mResource.getString(mPanelName+"_BORDER_"+keyword+"_LABEL");
        } catch (MissingResourceException e) {
            label = "Missing Label";
        }
        TitledBorder border = BorderFactory.createTitledBorder(label);
        Border margin = new EmptyBorder(-3,
                            0,
                            DIFFERENT_COMPONENT_SPACE,
                            0);
        /*
        Border margin = new EmptyBorder(0,
                            DIFFERENT_COMPONENT_SPACE-COMPONENT_SPACE,
                            DIFFERENT_COMPONENT_SPACE,
                            DIFFERENT_COMPONENT_SPACE-COMPONENT_SPACE);
        */
        return new CompoundBorder(border, margin);
    }

    //=== LABEL CREATION ====================
    protected JLabel makeJLabel(Icon i, String s, int a) {
        JLabel label = new JLabel();
        if (i != null)
            label.setIcon(i);
        if (s != null)
            label.setText(s);
        if (a != -1)
            label.setHorizontalAlignment(a);
        return label;
      }

    protected JLabel makeJLabel() {
        return makeJLabel((Icon)null, null, -1);
    }

    protected JLabel makeJLabel(String keyword) {
        return makeJLabel(keyword, (Icon) null, -1);
    }

    protected JLabel makeJLabel(String keyword, Icon i, int a) {
        return CMSAdminUtil.makeJLabel(mResource, mPanelName, keyword, i, a);
    }

    //===== TEXT FIELD CREATION ================
    protected JTextField makeJTextField(Document d, String s, int len) {
        return CMSAdminUtil.makeJTextField(d, s,len, this);
    }

    protected JTextField makeJTextField() {
        return makeJTextField(null, null, -1);
    }

    protected JTextField makeJTextField(int len) {
        return makeJTextField(null, null, len);
    }

    protected JTextField makeJTextField(String s) {
        return makeJTextField(null, s, -1);
    }

    protected JTextField makeJTextField(String s, int len) {
        return makeJTextField(null, s, len);
    }

    //==== PASSWORD FIELD CREATION ======================
    protected JPasswordField makeJPasswordField() {
        return makeJPasswordField(null, null, -1);
    }

    protected JPasswordField makeJPasswordField(Document d, String s, int len) {
        return CMSAdminUtil.makeJPasswordField(d, s,len, this);
    }

    protected JPasswordField makeJPasswordField(int len) {
        return makeJPasswordField(null, null, len);
    }

    protected JPasswordField makeJPasswordField(String s) {
        return makeJPasswordField(null, s, -1);
    }

    protected JPasswordField makeJPasswordField(String s, int len) {
        return makeJPasswordField(null, s, len);
    }

    //====== BUTTON CREATION ===========================
    protected JButton makeJButton(Icon i, String s) {
        JButton button = new JButton();
        if (s != null)
            button.setText(s);
        if (i != null)
            button.setIcon(i);

        button.addActionListener(this);
        return button;
    }

    protected JButton makeJButton() {
        return makeJButton((Icon)null, null);
    }

    protected JButton makeJButton(Icon i) {
        return makeJButton(i, null);
    }

    protected JButton makeJButton(String keyword) {
        return makeJButton(keyword, (Icon)null);
    }

    protected JButton makeJButton(String keyword, ActionListener listener) {
        return makeJButton(keyword, (Icon)null, listener);
    }

    protected JButton makeJButton(String keyword, Icon i) {
        return makeJButton(keyword, i, this);
    }

    protected JButton makeJButton(String keyword, Icon i, ActionListener listener) {
        return CMSAdminUtil.makeJButton(mResource, mPanelName, keyword, i, listener);
    }

    //===== CHECKBOX CREATION ========================
    protected JCheckBox makeJCheckBox(Icon i, String s, boolean b) {
        JCheckBox cb = new JCheckBox();
        if (s != null)
            cb.setText(s);
        if (i != null)
            cb.setIcon(i);
        cb.setSelected(b);
        cb.addActionListener(this);

        return cb;
    }

    protected JCheckBox makeJCheckBox() {
        return makeJCheckBox((Icon)null, null, false);
    }

    protected JCheckBox makeJCheckBox(Icon i) {
        return makeJCheckBox(i, null, false);
    }

    protected JCheckBox makeJCheckBox(Icon i, boolean b) {
        return makeJCheckBox(i, null, b);
    }

    protected JCheckBox makeJCheckBox(String keyword) {
        return makeJCheckBox(keyword, (Icon)null, false);
    }

    protected JCheckBox makeJCheckBox(String keyword, boolean b) {
        return makeJCheckBox(keyword, (Icon)null, b);
    }

    protected JCheckBox makeJCheckBox(String keyword, Icon i) {
        return makeJCheckBox(keyword, i, false);
    }

    protected JCheckBox makeJCheckBox(String keyword, Icon i, boolean val) {
        return CMSAdminUtil.makeJCheckBox(mResource, mPanelName, keyword, i, val, this);
    }

    //====== COMBOBOX CREATION ==========================
    protected JComboBox makeJComboBox(ComboBoxModel cbm) {
        JComboBox cb = new JComboBox();
        if (cbm != null)
            cb.setModel(cbm);
        cb.addItemListener(this);
        return cb;
    }

    protected JComboBox makeJComboBox() {
        return makeJComboBox((ComboBoxModel)null);
    }

    protected JComboBox makeJComboBox(String keyword) {
        String value = null;
        try {
            value = mResource.getString(mPanelName+"_COMBOBOX_"+keyword+"_DEFAULT");
        } catch (MissingResourceException e) {
        }
        JComboBox jcb = makeJComboBox((ComboBoxModel)null);
        String val = null;
        int ii = 0;
        do {
            try {
                val = mResource.getString(mPanelName+"_COMBOBOX_"+keyword+"_VALUE_"+ii);
                if (val != null) {
                    jcb.addItem(val);
                }
                ++ii;
            } catch (MissingResourceException e) {
                val = null;
            }
        } while (val != null);

        if (value != null)
            jcb.setSelectedItem(value);
        return jcb;
    }


    //==== LIST CREATION ============================

    protected JList makeJList(DefaultListModel listModel, int visibleCount) {
        return CMSAdminUtil.makeJList(listModel, visibleCount);
    }

    //===== RADIO BUTTON CREATION =======================
    protected JRadioButton makeJRadioButton(Icon i, String s, boolean b) {
        JRadioButton rb = new JRadioButton();
        if (s != null)
            rb.setText(s);
        if (i != null)
            rb.setIcon(i);
        rb.setSelected(b);
        rb.addActionListener(this);

        return rb;
    }

    protected JRadioButton makeJRadioButton() {
        return makeJRadioButton((Icon)null, null, false);
    }

    protected JRadioButton makeJRadioButton(Icon i) {
        return makeJRadioButton(i, null, false);
    }

    protected JRadioButton makeJRadioButton(Icon i, boolean b) {
        return makeJRadioButton(i, null, b);
    }

    protected JRadioButton makeJRadioButton(String keyword) {
        return makeJRadioButton(keyword, (Icon)null, false);
    }

    protected JRadioButton makeJRadioButton(String keyword, boolean b) {
        return makeJRadioButton(keyword, (Icon)null, b);
    }

    protected JRadioButton makeJRadioButton(String keyword, Icon i, boolean b) {
        return CMSAdminUtil.makeJRadioButton(mResource, mPanelName, keyword, i, b, this);
    }

    /**
	 * Create a panel with horizontally arranged, equally sized buttons
	 * The buttons are aligned to the right in the panel (if it is
	 * stretched beyond the length of the buttons)
	 *
	 * @param buttons An array of buttons for the panel
	 *
	 * @return A panel containing the buttons
	 */
    public static JPanel makeJButtonPanel( JButton[] buttons ) {
        return CMSAdminUtil.makeJButtonPanel(buttons);
	}

	public static JPanel makeJButtonPanel( JButton[] buttons, boolean isHelp) {
        return CMSAdminUtil.makeJButtonPanel(buttons, isHelp);
	}

	public static JPanel makeJButtonPanel( JButton[] buttons, boolean isHelp, boolean isConfig) {
        return CMSAdminUtil.makeJButtonPanel(buttons, isHelp, isConfig);
	}

    protected void startProgressStatus() {
        if (mNonWaitCursor == -1) {
            mCursor = mParent.getCursor();
            mNonWaitCursor = mCursor.getType();
        }
        mCursor = new Cursor(Cursor.WAIT_CURSOR);
        mParent.setCursor(mCursor);
        if (mAdminFrame != null)
            mAdminFrame.setCursor(mCursor);
        //UtilConsoleGlobals.getActivatedFrame().setCursor(mCursor);
    }

    protected void endProgressStatus() {
       if (mNonWaitCursor == -1)
           mNonWaitCursor = 0;
       mCursor = new Cursor(mNonWaitCursor);
       mParent.setCursor(mCursor);
        if (mAdminFrame != null)
           mAdminFrame.setCursor(mCursor);
       //UtilConsoleGlobals.getActivatedFrame().setCursor(mCursor);
    }

    /*==========================================================
	 * private methods
     *==========================================================*/
    private void setToolTip(String compKeyword, JComponent w) {
        CMSAdminUtil.setToolTip(mResource, mPanelName, compKeyword, w);
    }
}
