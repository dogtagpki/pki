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
import javax.swing.border.*;

import java.awt.*;
import java.awt.event.*;
import java.util.*;

import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;
import netscape.ldap.*;

/**
 *
 * Public-Key Cryptography Standards #11 (PKCS#11) Management dialog
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 */
public class PKCS11ManagementDialog extends AbstractDialog {

    KeyCertTaskInfo taskInfo;
    ConsoleInfo _consoleInfo;
    boolean setupComplete;

    ResourceSet resource = new ResourceSet("com.netscape.admin.certsrv.security.PKCS11ManagementResource");

    JPanel moduleList = new JPanel();
    JButton bClose;
    JButton bAdd;
    JButton bHelp;

    //since can't over load protected and I don't
    //want the interface to show so...

    private void privateHelpInvoked() {
        Help help = new Help(resource);
        help.help("PKCS11ManagementDialog", "help");
    }

    //since can't over load protected and I don't
    //want the interface to show so...
    private void privateCloseInvoked() {
        super.okInvoked();
    }

    private JPanel getModuleListPanel() {
        JPanel moduleListPanel = new JPanel();
        moduleListPanel.setLayout(new GridBagLayout());

        moduleListPanel.setBorder( new TitledBorder(
                new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(SuiConstants.COMPONENT_SPACE,
                SuiConstants.COMPONENT_SPACE, SuiConstants.COMPONENT_SPACE,
                SuiConstants.COMPONENT_SPACE)),
                resource.getString("PKCS11ManagementDialog", "title")));

        JScrollPane scrollPane = new JScrollPane(moduleList,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setBorder(
                new CompoundBorder(UITools.createLoweredBorder(),
                new EmptyBorder(VERT_COMPONENT_INSET,
                HORIZ_COMPONENT_INSET, VERT_COMPONENT_INSET,
                HORIZ_COMPONENT_INSET)));
        GridBagUtil.constrain(moduleListPanel, scrollPane, 0, 0, 1, 1,
                1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);


        return moduleListPanel;
    }


    private PKCS11AddModuleDialog addDialog;
    private void addInvoked() {
        addDialog.show();
        if (addDialog.isAdded()) {
            setupModules();
        }
    }

    class PKCS11ActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("CLOSE")) {
                privateCloseInvoked();
            } else if (e.getActionCommand().equals("ADD")) {
                addInvoked();

            } else if (e.getActionCommand().equals("HELP")) {
                privateHelpInvoked();
            }
        }
    }

    private JPanel getControlPanel() {
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        buttonPanel.setBorder(
                new EmptyBorder(SuiConstants.VERT_WINDOW_INSET, 0, 0, 0));


        PKCS11ActionListener listener = new PKCS11ActionListener();

        bClose = JButtonFactory.createCloseButton(listener);
        buttonPanel.add(bClose);
        buttonPanel.add( Box.createRigidArea(
                new Dimension(SuiConstants.COMPONENT_SPACE, 0)));

        bAdd = JButtonFactory.create(
                resource.getString("PKCS11ManagementDialog", "add"));
        buttonPanel.add(bAdd);
        bAdd.setActionCommand("ADD");
        bAdd.addActionListener(listener);
        buttonPanel.add( Box.createRigidArea(
                new Dimension(SuiConstants.SEPARATED_COMPONENT_SPACE, 0)));

        bHelp = JButtonFactory.createHelpButton(listener);
        buttonPanel.add(bHelp);

        JButtonFactory.resizeGroup(bHelp, bClose, bAdd);

        return buttonPanel;
    }


    private void setupModules() {
        taskInfo = new KeyCertTaskInfo(_consoleInfo);
        taskInfo.put("sie", KeyCertUtility.createTokenName(_consoleInfo));
        try {
            taskInfo.exec(taskInfo.SEC_LSMODULE);
        } catch (Exception e) {
            SuiOptionPane.showMessageDialog(
                    UtilConsoleGlobals.getActivatedFrame(), e.getMessage());
            setupComplete = false;
            return;
        }

        setModal(true);

        moduleList.removeAll();
        Vector modules = taskInfo.getResponse().getModuleList();
        for (int i = 0; i < modules.size(); i++) {
            moduleList.add(new JLabel((String) modules.elementAt(i)));
        }

        moduleList.doLayout();
        moduleList.repaint();
    }

    /**
      * Create a PKCS#11 managemnt dialog
      *
      * @param consoleInfo Console information
      *
      */
    public PKCS11ManagementDialog(ConsoleInfo consoleInfo) {
        super(null, "", true, NO_BUTTONS);

        setupComplete = true;

        setTitle(resource.getString("PKCS11ManagementDialog", "dialogTitle"));


        //Cursor oldCursor = UtilConsoleGlobals.getRootFrame().getCursor();
        UtilConsoleGlobals.getActivatedFrame().setCursor(
                new Cursor(Cursor.WAIT_CURSOR));

        _consoleInfo = consoleInfo;
        addDialog = new PKCS11AddModuleDialog(_consoleInfo);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout());
        mainPanel.add("Center", getModuleListPanel());
        mainPanel.add("South", getControlPanel());

        getContentPane().add(mainPanel);

        setMinimumSize(400, 275);
        //setResizable(false);

        moduleList.setLayout(new BoxLayout(moduleList, BoxLayout.Y_AXIS));

        setupModules();

        UtilConsoleGlobals.getActivatedFrame().setCursor(
                new Cursor(Cursor.DEFAULT_CURSOR));

        if (!setupComplete) {
            return;
        }

        show();
    }

    /*public static void main(String arg[]) {
         ConsoleInfo consoleInfo = null;
         String host = "buddha";

     JFrame f = new JFrame();
     f.setSize(500,500);
     f.show();
     UtilConsoleGlobals.setRootFrame(f);

     try {
      UIManager.setLookAndFeel("javax.swing.plaf.windows.WindowsLookAndFeel");
      SwingUtilities.updateComponentTreeUI(f.getContentPane());
     } catch (Exception e) {}

         try {
             consoleInfo = new ConsoleInfo("awing.mcom.com", 3890, "admin", "admin", "o=mcom.com");
             LDAPConnection connection = new LDAPConnection();
             consoleInfo.setAdminURL("http://"+host+".mcom.com:8081/");
             consoleInfo.setBaseDN("cn=admin-serv-"+host+", ou=Netscape SuiteSpot, o=Airius.com");
             consoleInfo.setCurrentDN("cn=admin-serv-"+host+", ou=Netscape SuiteSpot, o=Airius.com");
         } catch (Exception e) {System.out.println(e);}

     PKCS11ManagementDialog d = new PKCS11ManagementDialog(consoleInfo);
     }*/
}

