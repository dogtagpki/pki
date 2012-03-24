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
package com.netscape.admin.certsrv.security;

import java.awt.*;
import java.util.*;
import java.awt.event.*;
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import com.netscape.management.client.console.*;
import javax.swing.plaf.*;

import java.io.*;

/**
 *
 * Encryption panel used for server configuration.
 *
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 */
public class EncryptionPane extends JPanel implements ActionListener {

    private JCheckBox on;
    String title;

    JPanel top;
    JPanel cipherPane;

    private Vector cipherList = new Vector();

    boolean isFortezza = false;
    boolean isDomestic = false;

    ConsoleInfo _consoleInfo;
    String certdbName;

    JButton bCipherPref;
    JButton wizardButton;

    JLabel cipherTitle;
    JLabel tokenTitle;
    JLabel certTitle;


    Vector encryptionPaneListeners = new Vector();

    EncryptionPaneActionListener actionListener =
            new EncryptionPaneActionListener();

    KeyCertTaskInfo taskInfo;

    ResourceSet resource;

    /**
     *
     * @deprecated implement IEncryptionPaneListener instead
     */
    public void actionPerformed(ActionEvent e) {
    }


    class EncryptionPaneActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals(".doCipherSetting")) {
                for (int i = 0; i < encryptionPaneListeners.size(); i++) {
                    ((IEncryptionPaneListener)
                            (encryptionPaneListeners.elementAt(i))).
                            showCipherPreferenceDialog();
                }
            } else if (e.getActionCommand().equals("ENABLED")) {
                for (int i = 0; i < encryptionPaneListeners.size(); i++) {
                    ((IEncryptionPaneListener)
                            (encryptionPaneListeners.elementAt(i))).
                            sslStateChanged(on.isSelected());
                }
            } else {
                for (int i = 0; i < encryptionPaneListeners.size(); i++) {
                    Object cipher = getCipher(e.getActionCommand());
                    ((IEncryptionPaneListener)
                            (encryptionPaneListeners.elementAt(i))).
                            cipherStateChanged(isEnabled(cipher),
                            getCipherName(cipher), getToken(cipher),
                            getCertificateName(cipher));
                }
            }
        }
    }

    /**
      * Add a listener to the list that's notified each time a change to the selection occurs.
      *
      */
    public void addEncryptionPaneListener(
            IEncryptionPaneListener listener) {
        encryptionPaneListeners.addElement(listener);
    }



    /**
      *
      * Create an encryption panel
      *
      * @param consoleInfo server sepcific information
      */
    public EncryptionPane(ConsoleInfo consoleInfo) {
        this(consoleInfo, null);
    }

    /**
      *
      * Create an encryption panel
      *
      * @param consoleInfo server sepcific information
      * @param addPanel add customized panel into encryption panel
      */
    public EncryptionPane(ConsoleInfo consoleInfo, JPanel addPanel) {
        super();

        //actionListener

        _consoleInfo = consoleInfo;
        certdbName = KeyCertUtility.createTokenName(consoleInfo);


        setLayout(new BorderLayout());

        //setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        JPanel mainPane = new JPanel();
        //mainPane.setLayout(new BorderLayout());
        mainPane.setLayout(new GridBagLayout());


        resource = new ResourceSet("com.netscape.admin.certsrv.security.EncryptionPaneResource");

        on = new JCheckBox(resource.getString("EncryptionPane", "enableSSL"),
                false);
        on.setActionCommand("ENABLED");
        on.addActionListener(new CipherPaneToggleListener());

        on.addActionListener(actionListener);


        top = new JPanel();
        top.setAlignmentX(0.0f);
        top.setLayout(new BoxLayout(top, BoxLayout.X_AXIS));
        top.add(on);

        //mainPane.setBorder(new ToggleBorder(top, SwingConstants.TOP));
        mainPane.setBorder( new CompoundBorder(
                new ToggleBorder(top, SwingConstants.TOP),
                new EmptyBorder(0, SuiConstants.COMPONENT_SPACE,
                SuiConstants.COMPONENT_SPACE, 0)));

        GridBagUtil.constrain(mainPane, top, 0, 0, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTHWEST, GridBagConstraints.NONE,
                0, 0, 0, 0);


        cipherPane = new JPanel();
        cipherPane.setLayout(new BorderLayout());

        GridBagUtil.constrain(mainPane, cipherPane, 0, 1, 2, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0,
                SuiConstants.COMPONENT_SPACE, 0);

        bCipherPref = JButtonFactory.create(
                resource.getString("EncryptionPane", "cipherPrefTitle"));
        wizardButton = JButtonFactory.create(
                resource.getString("EncryptionPane", "wizardTitle"));

        bCipherPref.setActionCommand(".doCipherSetting");
        bCipherPref.addActionListener(this);

        bCipherPref.addActionListener(actionListener);

        wizardButton.setActionCommand("WIZARD");
        wizardButton.addActionListener(new wizardButtonActionListener());


        updateEncryptionUI();

        add("North", mainPane);


        //other pane contain server specific pane and a wizrad button.
        JPanel otherPane = new JPanel();
        otherPane.setLayout(new BoxLayout(otherPane, BoxLayout.Y_AXIS));
        //otherPane.setLayout(new GridBagLayout());

        if (addPanel != null) {
            otherPane.add(addPanel);
        }

        otherPane.add( Box.createRigidArea(
                new Dimension(0, SuiConstants.COMPONENT_SPACE)));

        add("Center", otherPane);

        JPanel buttonPane = new JPanel();
        buttonPane.setLayout(new GridBagLayout());
        GridBagUtil.constrain(buttonPane, wizardButton, 0, 0, 1, 1,
                0.0, 0.0, GridBagConstraints.SOUTHWEST,
                GridBagConstraints.NONE, 0, 0, 0, 0);

        GridBagUtil.constrain(buttonPane, Box.createHorizontalGlue(),
                1, 0, 1, 1, 1.0, 0.0, GridBagConstraints.SOUTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        //add("South", wizardButton);
        add("South", buttonPane);

    }

    /**
      * Returns a vector containing cipher objects
      * @see #getCipherCount
      * @see #getCipherAt
      *
      * @return a vector contains cipher object as element
      */
    public Vector getCipherList() {
        return cipherList;
    }


    /**
      * Returns the number of cipher objects in encryption pane
      *
      * @see #getCipherList
      * @see #getCipherAt
      *
      * @return the number of cipher object in encryption pane
      */
    public int getCipherCount() {
        return cipherList.size();
    }

    /**
      * Returns the cipher object at the specified index.
      *
      * @param      index   an index into cipher list.
      *
      * @see #getCipherList
      * @see #getCipherCount
      *
      * @return the number of cipher object in encryption pane
      */
    public Object getCipherAt(int index) {
        return cipherList.elementAt(index);
    }

    private CipherEntry getCipher(String cipherName) {
        int count = getCipherCount();
        for (int i = count - 1; i >= 0; i--) {
            Object cipher = getCipherAt(i);
            if (cipherName.equals(getCipherName(cipher))) {
                return ((CipherEntry) cipher);
            }
        }
        return null;
    }


    /**
      * Return cipher name
      *
      * @param cipher cipher object
      *
      * @return cipher name
      */
    public String getCipherName(Object cipher) {
        return ((CipherEntry) cipher).getCipherName();
    }


    /**
      * Return selected token name
      *
      * @param cipher cipher object
      *
      * @return selected token
      */
    public String getToken(Object cipher) {
        return ((CipherEntry) cipher).getSelectedToken();
    }


    /**
      * Set token selection.  Default will be taken if no selection
      * match the token user specified.
      *
      * @param cipher cipher object
      *
      */
    public void setToken(Object cipher, String token) {
        ((CipherEntry) cipher).setSelectedToken(token);
    }



    /**
      * Return certificate name
      *
      * @param cipher cipher object
      *
      * @return certificate name
      *
      */
    public String getCertificateName(Object cipher) {
        return ((CipherEntry) cipher).getSelectedCertName();

    }

    /**
      * Set the certificate field to the specified certificate name
      *
      * @param cipher cipher object
      * @param certificateName certificate name
      *
      */
    public void setCertificateName(Object cipher, String certificateName) {
        ((CipherEntry) cipher).setSelectedCert(certificateName);
    }

    /**
      * Return cipher state, true a cipher is enabled
      *
      * @param cipher cipher object
      *
      * @return true if a cipher is enabled false other wise
      */
    public boolean isEnabled(Object cipher) {
        return ((CipherEntry) cipher).isEnabled();
    }

    /**
      * Set cipher state
      *
      * @param cipher cipher object
      * @param on     cipher state
      *
      */
    public void setEnabled(Object cipher, boolean on) {
        ((CipherEntry) cipher).setSelected(on);
    }


    /**
      * Return encryption setting
      *
      * @return true if SSL on/off is on.
      */
    public boolean isEncryptionEnabled() {
        return on.isSelected();
        //return ((Boolean)(encryptionOnOff.getValue())).booleanValue();
    }

    /**
      * Set encryption on/off
      *
      */
    public void setEncryption(boolean on) {
        setEnableAll(on);
        this.on.setSelected(on);
        //encryptionOnOff.setValue(new Boolean(on));
    }

    /**
      * Return certificate database file name
      *
      * @param certificate database file name
      */
    public String getCertificateDBName() {
        return certdbName;
    }

    /**
      * A convenience function to setup an cipher.
      * If no matching cipherName found in the encryption
      * pane, this function will do nothing.
      *
      * @param on cipher state
      * @param cipherName cipher name
      * @param token token name
      * @param personality personality name
      *
      * @see #setEnabled
      */
    public void setCipherSetting(boolean on, String cipherName,
            String token, String personality) {
        int count = getCipherCount();
        for (int i = count - 1; i >= 0; i--) {
            Object cipher = getCipherAt(i);
            if (cipherName.equals(getCipherName(cipher))) {
                setEnabled(cipher, on);
                setToken(cipher, token);
                setCertificateName(cipher, personality);
            }
        }
    }

    /**
      *
      * @return true if fortezza is detected on the server
      */
    public boolean hasFortezza() {
        return isFortezza;
    }


    /**
      *
      * @return true if a domestic server is detected
      */
    public boolean isSecurityDomestic() {
        return isDomestic;
    }

    /**
      *
      * @return encryption pane
      */
    public JPanel getPanel() {
        return this;
    }



    private JLabel leftAlignLabel(String label) {
        return new JLabel(label, JLabel.LEFT);
    }

    private void updateCipherEntry() {
    }


    /**
      *  Update ui
      *
      */
    public void refresh() {
        updateEncryptionUI();
    }

    JPanel cPane = new JPanel();
    private void updateEncryptionUI() {
        cPane.removeAll();

        cPane.setLayout(new GridBagLayout());

        int y = 0;

        cipherTitle =
                leftAlignLabel(resource.getString("EncryptionPane", "cipherTitle"));
        tokenTitle =
                leftAlignLabel(resource.getString("EncryptionPane", "tokenTitle"));
        certTitle =
                leftAlignLabel(resource.getString("EncryptionPane", "certTitle"));

        GridBagUtil.constrain(cPane, cipherTitle, 0, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                SuiConstants.HORIZ_COMPONENT_INSET, 0,
                SuiConstants.COMPONENT_SPACE,
                SuiConstants.SEPARATED_COMPONENT_SPACE);
        GridBagUtil.constrain(cPane, tokenTitle, 1, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, SuiConstants.COMPONENT_SPACE,
                SuiConstants.SEPARATED_COMPONENT_SPACE);
        GridBagUtil.constrain(cPane, certTitle, 2, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, SuiConstants.COMPONENT_SPACE, 0);

        taskInfo = new KeyCertTaskInfo(_consoleInfo);
        taskInfo.clear();

        taskInfo.put("sie", certdbName);

        try {
            taskInfo.exec(taskInfo.SEC_LSTOKEN);
        } catch (Exception e) {
            SuiOptionPane.showMessageDialog(
                    UtilConsoleGlobals.getActivatedFrame(), e.getMessage());
            return;
        }

        cipherList = taskInfo.getResponse().getFamilyList();

        isFortezza = taskInfo.getResponse().isSecurityFortezza();
        isDomestic = taskInfo.getResponse().isSecurityDomestic();


        for (int index = cipherList.size() - 1; index >= 0; index--) {
            CipherEntry cipher = (CipherEntry)(cipherList.elementAt(index));
            cipher.getCipherCheckBox().addActionListener(this);
            cipher.getTokenComboBox().addActionListener(this);
            cipher.getCertComboBox().addActionListener(this);

            String name = cipher.getCipherCheckBox().getText();
            cipher.getCipherCheckBox().setActionCommand(name);
            cipher.getTokenComboBox().setActionCommand(name);
            cipher.getCertComboBox().setActionCommand(name);

            cipher.getCipherCheckBox().addActionListener(actionListener);
            cipher.getTokenComboBox().addActionListener(actionListener);
            cipher.getCertComboBox().addActionListener(actionListener);

            GridBagUtil.constrain(cPane, cipher.getCipherCheckBox(), 0,
                    ++y, 1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                    GridBagConstraints.BOTH, 0, 0,
                    SuiConstants.COMPONENT_SPACE,
                    SuiConstants.COMPONENT_SPACE);
            GridBagUtil.constrain(cPane, cipher.getTokenComboBox(), 1,
                    y, 1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                    GridBagConstraints.BOTH, 0, 0,
                    SuiConstants.COMPONENT_SPACE,
                    SuiConstants.COMPONENT_SPACE);
            GridBagUtil.constrain(cPane, cipher.getCertComboBox(), 2,
                    y, 1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                    GridBagConstraints.BOTH, 0, 0,
                    SuiConstants.COMPONENT_SPACE,
                    SuiConstants.COMPONENT_SPACE);
        }

        GridBagUtil.constrain(cPane, bCipherPref, 1, ++y, 2, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0,
                SuiConstants.COMPONENT_SPACE);


        setEnableAll(false);
        cipherPane.add("North", cPane);
        cPane.validate();
        cPane.repaint();
    }

    class wizardButtonActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("WIZARD")) {
                //save the old setting
                Vector oldEntry = getCipherList();

                //lunch the wizard
                KeyCertWizard wizard = new KeyCertWizard(_consoleInfo);

                UtilConsoleGlobals.getActivatedFrame().setCursor(
                        new Cursor(Cursor.WAIT_CURSOR));

                //update the cipher entries
                //well it is inefficient, but unless more api
                //is added to wizard it self we can't tell if
                //a new cert is been added or not
                updateEncryptionUI();

                //restore the setting
                for (int i = oldEntry.size() - 1; i >= 0; i--) {
                    Object cipher = oldEntry.elementAt(i);
                    setCipherSetting(isEnabled(cipher),
                            getCipherName(cipher), getToken(cipher),
                            getCertificateName(cipher));
                }

                setEnableAll(isEncryptionEnabled());

                UtilConsoleGlobals.getActivatedFrame().setCursor(
                        new Cursor(Cursor.DEFAULT_CURSOR));

            }
        }
    }


    private void setEnableAll(boolean enable) {
        int count = getCipherCount();
        for (int i = 0; i < count; i++) {
            ((CipherEntry) cipherList.elementAt(i)).setEnabledAll(enable);
        }
        bCipherPref.setEnabled(enable);
        cipherTitle.setEnabled(enable);
        tokenTitle.setEnabled(enable);
        certTitle.setEnabled(enable);
        invalidate();
        repaint();
    }

    class CipherPaneToggleListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("ENABLED")) {
                setEnableAll(on.isSelected());
                EncryptionPane.this.actionPerformed(e);
                validate();
                repaint();
            }
        }
    }

    class ToggleBorder extends EtchedBorder {
        private JComponent _switchPanel;
        private int _switchAlign;

        public ToggleBorder(JComponent sp, int align) {
            _switchPanel = sp;
            _switchAlign = align;
        }

        public void paintBorder(Component c, Graphics g, int x, int y,
                int width, int height) {
            Color save = g.getColor();

            int top = y + (_switchPanel.getHeight() >> 1);
            int new_height = height - top;

            BorderUIResource.getEtchedBorderUIResource().paintBorder(c,
                    g, x, top, width, new_height);
        }
    }

}
