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

import com.netscape.management.client.console.ConsoleInfo;

import javax.swing.*;
import javax.swing.JFileChooser;

import java.awt.*;
import java.awt.event.*;
import java.util.*;

import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


class PKCS11AddModuleDialog extends AbstractDialog {

    KeyCertTaskInfo taskInfo;

    ResourceSet resource = new ResourceSet("com.netscape.admin.certsrv.security.PKCS11ManagementResource");

    JRadioButton _isDLL;
    JRadioButton _isJAR;
    JTextField _dllname = new JTextField(10);
    JTextField _filename = new JTextField(10);

    boolean moduleAdded;

    protected boolean isAdded() {
        return moduleAdded;
    }

    protected void okInvoked() {
        moduleAdded = false;
        taskInfo.clear();

        taskInfo.put("filename", _filename.getText());
        taskInfo.put("format", _isDLL.isSelected() ? "dll" : "jar");
        if (_isDLL.isSelected())
            taskInfo.put("dllname", _dllname.getText());

        Response response = null;
        try {
            response = taskInfo.exec(taskInfo.SEC_ADDMOD);
        } catch (Exception e) {
            SuiOptionPane.showMessageDialog(
                    UtilConsoleGlobals.getActivatedFrame(), e.getMessage());
            return;
        }

        try {
            Message m = (Message)(response.getMessages().elementAt(0));
            MessageDialog.messageDialog(m);
            moduleAdded = m.isSuccess();
        } catch (Exception ex) {}

        if (((Message) response.getMessages().elementAt(0)).getStatus()
                == Message.NMC_SUCCESS)
            super.okInvoked();
    }

    protected void helpInvoked() {
        Help help = new Help(resource);
        help.help("PKCS11AddModuleDialog", "help");
    }


    /**
      * Listen to changes (key strokes or change in text area or text field)
      * then determain (call setEnableNextButton()) if wizard can proceed
      */
    class MyActionListener implements KeyListener, ActionListener {
        public void keyTyped(KeyEvent e) {}
        public void keyPressed(KeyEvent e) {}
        public void keyReleased(KeyEvent e) {}
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("ENABLED"))
                _dllname.setEnabled(_isDLL.isSelected());
        }
    }

    public PKCS11AddModuleDialog(ConsoleInfo consoleInfo) {
        super(null, "", true, OK | CANCEL | HELP);

        setTitle(resource.getString("PKCS11AddModuleDialog", "dialogTitle"));


        taskInfo = new KeyCertTaskInfo(consoleInfo);

        Container mainPane = getContentPane();
        mainPane.setLayout(new GridBagLayout());

        _isDLL = new JRadioButton(
                resource.getString("PKCS11AddModuleDialog", "DLL"), true);
        _isJAR = new JRadioButton(
                resource.getString("PKCS11AddModuleDialog", "JAR"), false);

        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(_isDLL);
        buttonGroup.add(_isJAR);

        _isDLL.setActionCommand("ENABLED");
        _isDLL.addActionListener(new MyActionListener());
        _isJAR.setActionCommand("ENABLED");
        _isJAR.addActionListener(new MyActionListener());

        GridBagUtil.constrain(mainPane,
                new JLabel( resource.getString("PKCS11AddModuleDialog",
                "fileType")), 0, 0, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(mainPane, _isDLL, 0, 1, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(mainPane, _dllname, 1, 1, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(mainPane, _isJAR, 0, 2, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(mainPane, Box.createVerticalGlue(), 0, 3,
                1, 1, 1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        GridBagUtil.constrain(mainPane,
                new JLabel( resource.getString("PKCS11AddModuleDialog",
                "fileName")), 0, 4, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(mainPane, _filename, 0, 5, 1, 1, 1.0,
                1.0, GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0, COMPONENT_SPACE, 0);

        //getContentPane().add(mainPane);

        pack();
        setMinimumSize(getSize());
    }

}

