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

import javax.swing.*;
import javax.swing.border.*;

import java.awt.*;
import java.awt.event.*;
import java.util.*;

import com.netscape.management.client.console.ConsoleInfo;


import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

class CRLDeleteCertDialog extends AbstractDialog implements SuiConstants {



    ConsoleInfo _consoleInfo;

    KeyCertTaskInfo _taskInfo;
    static boolean delete = false;

    String _sie;

    JButton bClose;
    JButton bDelete;
    JButton bHelp;

    CertInfo _certInfo;
    ResourceSet _resource;
    String _crlname;
    String _listtype;

    CRLCertInfoPane _crlCertInfoPane;


    class CRLDeleteCertActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("DELETE")) {
                //call delete cert cgi
                _taskInfo.clear();
                _taskInfo.put("formop", "D");
                _taskInfo.put("crlname", _crlname);
                _taskInfo.put("sie", _sie);
                _taskInfo.put("list_type", _listtype);

                Response response = null;
                try {
                    response = _taskInfo.exec(_taskInfo.SEC_ECRL);
                } catch (Exception error) {
                    SuiOptionPane.showMessageDialog(
                            UtilConsoleGlobals.getActivatedFrame(),
                            error.getMessage());
                    return;
                }
                if (!(((Message)(response.getMessages().elementAt(0))).
                        isFailure())) {
                    delete = true;
                    setVisible(false);
                } else {
                    try {
                        MessageDialog.messageDialog( (Message)
                                (response.getMessages().elementAt(0)));
                    } catch (Exception e2) {
                        //shouldn't even be here in the first place.  if cgi fail or return nothing
                        //then it should be handle right after KeyCertTaskInfo.exec(...) is called
                        //If exception occure here here then something is really mess up.
                        Debug.println("Error in decoding server messages");
                    }
                }
            } else if (e.getActionCommand().equals("CLOSE")) {
                setVisible(false);
            } else if (e.getActionCommand().equals("HELP")) {
                Help help = new Help(_resource);
                help.help("CRLDeleteCertDialog", "help");
            }
        }
    }

    public boolean isDeleted() {
        return delete;
    }

    protected void show(String crlname, String list_type) {
        delete = false;
        _crlname = crlname;
        _listtype = list_type;

        _taskInfo.clear();
        _taskInfo.put("sie", _sie);
        _taskInfo.put("crlname", crlname);
        _taskInfo.put("list_type", list_type);
        try {
            _taskInfo.exec(_taskInfo.SEC_ECRL);
        } catch (Exception e) {
            SuiOptionPane.showMessageDialog(
                    UtilConsoleGlobals.getActivatedFrame(), e.getMessage());
            return;
        }

        if (_taskInfo.getResponse().hasCertInfo()) {
            setInfo(_taskInfo.getResponse().getCertInfo());
            super.show();
        } else {
            Object[] message = new Object[2];
            message[0] = _resource.getString("CRLDeleteCertDialog", "error");
            SuiOptionPane.showMessageDialog(
                    UtilConsoleGlobals.getActivatedFrame(), message);
        }
    }

    private void setInfo(CertInfo certInfo) {
        _certInfo = certInfo;

        _crlCertInfoPane.setCertInfo(certInfo);
    }


    public CRLDeleteCertDialog(ConsoleInfo consoleInfo,
            ResourceSet resource) {
        super(null, "", true, NO_BUTTONS);

        _consoleInfo = consoleInfo;
        _sie = KeyCertUtility.createTokenName(_consoleInfo);
        _resource = resource;
        _taskInfo = new KeyCertTaskInfo(consoleInfo);

        _crlCertInfoPane = new CRLCertInfoPane(resource);

        Container mainPane = getContentPane();
        mainPane.setLayout(new GridBagLayout());

        GridBagUtil.constrain(mainPane, _crlCertInfoPane, 0, 0, 4, 1,
                1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0,
                SuiConstants.DIFFERENT_COMPONENT_SPACE, 0);


        CRLDeleteCertActionListener listener =
                new CRLDeleteCertActionListener();

        bClose = JButtonFactory.createCloseButton(listener);
        GridBagUtil.constrain(mainPane, bClose, 1, 1, 1, 1, 1.0, 0.0,
                GridBagConstraints.SOUTHEAST, GridBagConstraints.NONE,
                0, 0, 0, SuiConstants.COMPONENT_SPACE);


        bDelete = JButtonFactory.createDeleteButton(listener);
        GridBagUtil.constrain(mainPane, bDelete, 2, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.SOUTHEAST, GridBagConstraints.NONE,
                0, 0, 0, SuiConstants.SEPARATED_COMPONENT_SPACE);


        bHelp = JButtonFactory.createHelpButton(listener);
        GridBagUtil.constrain(mainPane, bHelp, 3, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.SOUTHEAST, GridBagConstraints.NONE,
                0, 0, 0, 0);



        JButtonFactory.resizeGroup(bHelp, bClose, bDelete);

        setSize(400, 225);
        setResizable(false);
    }

    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     f.setSize(400,400);
     f.show();

     try {
      UIManager.setLookAndFeel("javax.swing.plaf.windows.WindowsLookAndFeel");
      SwingUtilities.updateComponentTreeUI(f.getContentPane());
     } catch (Exception e) {}


     CRLDeleteCertDialog d = new CRLDeleteCertDialog(new ConsoleInfo(), new ResourceSet("com.netscape.admin.certsrv.security.CertManagementResource"));
     d.show();
     }*/
}

