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
import com.netscape.management.client.util.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;
import javax.swing.event.*;

import java.awt.*;
import java.awt.event.*;
import java.util.*;

import netscape.ldap.*;

import com.netscape.management.nmclf.*;

/**
 *
 * Certificate Revocation List management dialog.
 * This is a self contain dialog, that allow use to
 * add/remove certificate fron a certificate revocation
 * list.  This is only the front end, the actuall work
 * of removing and adding certificate will be handled
 * by the server
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 */
public class CRLManagementDialog extends AbstractDialog {

    JButton bClose;
    JButton bView;
    JButton bAdd;
    JButton bHelp;

    ConsoleInfo _consoleInfo;

    ResourceSet resource = new ResourceSet("com.netscape.admin.certsrv.security.CertManagementResource");

    AddCRLCertificateDialog addCRLCertificateDialog;

    CRLTable _crlTable;


    private void parseCRLInfo(String response) {
    }

    //since can't over load protected and I don't
    //want the interface to show so...
    private void privateHelpInvoked() {
        Help help = new Help(resource);
        help.help("CRLManagementDialog", "help");
    }


    //since can't over load protected and I don't
    //want the interface to show so...
    private void privateCloseInvoked() {
        super.okInvoked();
    }

    class CertManagementActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("CLOSE")) {
                privateCloseInvoked();
            } else if (e.getActionCommand().equals("HELP")) {
                privateHelpInvoked();
            } else if (e.getActionCommand().equals("VIEW")) {
                _crlTable.showCert();
            } else if (e.getActionCommand().equals("ADD")) {
                addCRLCertificateDialog.show();
            }
        }
    }


    private JPanel getCertListPane() {
        JPanel certListPane = new JPanel();
        certListPane.setLayout(new GridBagLayout());
        certListPane.setBorder( new TitledBorder(
                new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)),
                resource.getString("CRLManagementDialog", "certificate")));


        GridBagUtil.constrain(certListPane,
                new JLabel(
                resource.getString("CRLManagementDialog", "certDB")),
                0, 0, 1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.NONE, 0, 0, COMPONENT_SPACE, 0);


        GridBagUtil.constrain(certListPane,
                new JLabel(
                resource.getString("CRLManagementDialog", "defaultToken"),
                JLabel.RIGHT), 1, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        _crlTable = new CRLTable(_consoleInfo, resource);
        GridBagUtil.constrain(certListPane, _crlTable, 0, 1, 2, 1, 1.0,
                1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);


        return certListPane;
    }

    class AddCRLCertificateDialog extends AbstractDialog {
        KeyCertTaskInfo _taskInfo;
        JTextField _filename;
        JRadioButton _ckl;
        JRadioButton _crl;

        public AddCRLCertificateDialog(ConsoleInfo consoleInfo) {
            super(null,
                    CRLManagementDialog.this.resource.getString("AddCRLCertificateDialog",
                    "dialogTitle"), true, OK | CANCEL | HELP);
            _taskInfo = new KeyCertTaskInfo(consoleInfo);

            Container p = getContentPane();
            p.setLayout(new GridBagLayout());

            _crl = new JRadioButton(
                    resource.getString("AddCRLCertificateDialog",
                    "crlfiletype"), true);
            _ckl = new JRadioButton(
                    resource.getString("AddCRLCertificateDialog",
                    "cklfiletype"), false);

            ButtonGroup buttonGroup = new ButtonGroup();
            buttonGroup.add(_crl);
            buttonGroup.add(_ckl);

            GridBagUtil.constrain(p,
                    new JLabel(
                    resource.getString("AddCRLCertificateDialog",
                    "filename")), 0, 0, 2, 1, 1.0, 0.0,
                    GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                    0, 0, SuiConstants.COMPONENT_SPACE, 0);

            _filename = new JTextField(30);
            GridBagUtil.constrain(p, _filename, 0, 1, 2, 1, 1.0, 0.0,
                    GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                    0, 0, 0, 0);

            GridBagUtil.constrain(p, (Component)_crl, 0, 2, 2, 1, 1.0,
                    0.0, GridBagConstraints.NORTH,
                    GridBagConstraints.BOTH, 0, 0, 0, 0);

            GridBagUtil.constrain(p, (Component)_ckl, 0, 3, 2, 1, 1.0,
                    0.0, GridBagConstraints.NORTH,
                    GridBagConstraints.BOTH, 0, 0, 0, 0);

            pack();
            setResizable(false);
        }


        CRLAddCertDialog _crlAddCertDialog =
                new CRLAddCertDialog(_consoleInfo, resource);
        protected void okInvoked() {
            _crlAddCertDialog.show(_filename.getText(),
                    _ckl.isSelected() ? "CKL" : "CRL");
            setVisible(false);
            if (_crlAddCertDialog.isModified()) {
                CertInfo certInfo = _crlAddCertDialog.getCertInfo();
                //only need the first line where the issuer's name locate
                String issuer = certInfo.getIssuer();
                _crlTable.addCert(
                        issuer.substring(0, issuer.indexOf("\n")),
                        certInfo.getValidTo(),
                        _ckl.isSelected() ? "CKL" : "CRL");
                UtilConsoleGlobals.getActivatedFrame().setCursor(
                        new Cursor(Cursor.WAIT_CURSOR));
                _crlTable.update();
                UtilConsoleGlobals.getActivatedFrame().setCursor(
                        new Cursor(Cursor.DEFAULT_CURSOR));
            }
        }

        protected void helpInvoked() {
            Help help = new Help(resource);
            help.help("AddCRLCertificateDialog", "help");
        }
    }


    private JPanel getControlButtons() {
        JPanel controlPanel = new JPanel();
        controlPanel.setLayout(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        controlPanel.setBorder(
                new EmptyBorder(SuiConstants.VERT_WINDOW_INSET, 0, 0, 0));

        CertManagementActionListener listener =
                new CertManagementActionListener();

        bClose = JButtonFactory.createCloseButton(listener);
        controlPanel.add(bClose);

        controlPanel.add( Box.createRigidArea(
                new Dimension(SuiConstants.COMPONENT_SPACE, 0)));

        bView = JButtonFactory.create(
                resource.getString("CRLManagementDialog", "view"));
        bView.addActionListener(listener);
        bView.setActionCommand("VIEW");
        controlPanel.add(bView);

        controlPanel.add( Box.createRigidArea(
                new Dimension(SuiConstants.COMPONENT_SPACE, 0)));

        bAdd = JButtonFactory.create(
                resource.getString("CRLManagementDialog", "add"));
        bAdd.addActionListener(listener);
        bAdd.setActionCommand("ADD");
        controlPanel.add(bAdd);

        controlPanel.add( Box.createRigidArea(
                new Dimension(SuiConstants.SEPARATED_COMPONENT_SPACE, 0)));

        bHelp = JButtonFactory.createHelpButton(listener);
        controlPanel.add(bHelp);

        JButtonFactory.resizeGroup(bHelp, bClose, bView, bAdd);

        return controlPanel;
    }

    /**
      * Create a Certificate Revocation List Management dialog
      *
      * @param consoleInfo Console information
      *
      */
    public CRLManagementDialog(ConsoleInfo consoleInfo) {
        super(null, "", true, NO_BUTTONS);

        _consoleInfo = consoleInfo;
        addCRLCertificateDialog = new AddCRLCertificateDialog(_consoleInfo);


        UtilConsoleGlobals.getActivatedFrame().setCursor(
                new Cursor(Cursor.WAIT_CURSOR));

        //_consoleInfo = consoleInfo;

        setTitle(resource.getString("CRLManagementDialog", "title"));

        JPanel mainPane = new JPanel();
        mainPane.setLayout(new BorderLayout());


        mainPane.add("Center", getCertListPane());

        mainPane.add("South", getControlButtons());

        getContentPane().add(mainPane);

        //pack();
        setMinimumSize(400, 400);
        //setResizable(false);

        UtilConsoleGlobals.getActivatedFrame().setCursor(
                new Cursor(Cursor.DEFAULT_CURSOR));

        if (!(_crlTable.isTableSetup())) {
            return;
        }

        validate();
        invalidate();
        show();
    }


    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     f.setSize(200,200);
     f.show();
     UtilConsoleGlobals.setActivatedFrame(f);
     try {
      UIManager.setLookAndFeel("javax.swing.plaf.windows.WindowsLookAndFeel");
      SwingUtilities.updateComponentTreeUI(f.getContentPane());
     } catch (Exception e) {}

     CRLManagementDialog d = new CRLManagementDialog(new ConsoleInfo());
     }*/
}
