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

import com.netscape.management.nmclf.*;

/**
 *
 * Certificate management dialog.
 * This is a self contain dialog, that allow use to
 * view, delete, and change the trut status of a certificate.
 * This is only the front end, the actuall work
 * of looking up, delete, and modified certificate are handled
 * at the server side.
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 */
public class CertManagementDialog extends AbstractDialog {

    CertListTable certListTable;
    KeyCertTaskInfo taskInfo;
    ConsoleInfo _consoleInfo;

    JButton bClose;
    JButton bEdit;
    JButton bHelp;

    ResourceSet resource = new ResourceSet("com.netscape.admin.certsrv.security.CertManagementResource");

    //since can't over load protected and I don't
    //want the interface to show so...
    private void privateHelpInvoked() {
        Help help = new Help(resource);
        help.help("CertManagementDialog", "help");
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
            } else if (e.getActionCommand().equals("EDIT")) {
                certListTable.showCert();
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
                resource.getString("CertManagementDialog", "certificate")));


        GridBagUtil.constrain(certListPane,
                new JLabel(
                resource.getString("CertManagementDialog", "certDB")),
                0, 0, 1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.NONE, 0, 0, COMPONENT_SPACE, 0);


        GridBagUtil.constrain(certListPane,
                new JLabel( resource.getString("CertManagementDialog",
                "defaultToken"), JLabel.RIGHT), 1, 0, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(certListPane, certListTable, 0, 1, 2, 1,
                1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);


        return certListPane;
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

        bEdit = JButtonFactory.create(
                resource.getString("CertManagementDialog", "edit"));
        bEdit.addActionListener(listener);
        bEdit.setActionCommand("EDIT");
        controlPanel.add(bEdit);

        controlPanel.add( Box.createRigidArea(
                new Dimension(SuiConstants.SEPARATED_COMPONENT_SPACE, 0)));

        bHelp = JButtonFactory.createHelpButton(listener);
        controlPanel.add(bHelp);

        JButtonFactory.resizeGroup(bHelp, bClose, bEdit);

        return controlPanel;
    }



    /**
      * Create an certificate management dialog to
      * manage remote certificate database
      *
      * @param consoleInfo Console information
      *
      */
    public CertManagementDialog(ConsoleInfo consoleInfo) {
        super(null, "", true, NO_BUTTONS);

        UtilConsoleGlobals.getActivatedFrame().setCursor(
                new Cursor(Cursor.WAIT_CURSOR));

        _consoleInfo = consoleInfo;

        setTitle(resource.getString("CertManagementDialog", "title"));

        JPanel mainPane = new JPanel();
        mainPane.setLayout(new BorderLayout());

        certListTable = new CertListTable(
                KeyCertUtility.createTokenName(_consoleInfo), consoleInfo);
        mainPane.add("Center", getCertListPane());
        mainPane.add("South", getControlButtons());

        getContentPane().add(mainPane);

        //pack();
        setMinimumSize(400, 400);
        //setResizable(false);

        UtilConsoleGlobals.getActivatedFrame().setCursor(
                new Cursor(Cursor.DEFAULT_CURSOR));

        if (!(certListTable.isTableSetup())) {
            return;
        }

        show();
    }

    /**
      * Create an certificate management dialog to
      * manage local trust database.
      *
      *
      */
    public CertManagementDialog() {
        super(null, "", true, NO_BUTTONS);

        setTitle(resource.getString("CertManagementDialog", "title"));

        JPanel mainPane = new JPanel();
        mainPane.setLayout(new BorderLayout());

        certListTable = new CertListTable();
        mainPane.add("Center", getCertListPane());
        mainPane.add("South", getControlButtons());

        getContentPane().add(mainPane);

        setSize(400, 400);

        if (!(certListTable.isTableSetup())) {
            return;
        }

        show();
    }
}
