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

class CRLAddCertDialog extends AbstractDialog implements SuiConstants {

    ConsoleInfo _consoleInfo;

    KeyCertTaskInfo _taskInfo;
    static boolean modified = false;

    String _sie;
    String _filename;
    String _listtype;

    JButton bClose;
    JButton bAction;
    JButton bHelp;

    CertInfo _certInfo;
    ResourceSet _resource;


    CRLCertInfoPane _crlCertInfoPane;


    class CRLAddCertActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            modified = false;
            if (e.getActionCommand().equals("ACTION")) {
                //call delete cert cgi
                _taskInfo.clear();
                _taskInfo.put("crl_file", _filename);
                _taskInfo.put("sie", _sie);
                _taskInfo.put(
                        (_certInstInfo.get("crl_action").equals("add"))
                        ? "addbutton":"repbutton", "1");
                _taskInfo.put("list_type", _listtype);

                Response response = null;
                try {
                    response = _taskInfo.exec(_taskInfo.SEC_ICRL);
                } catch (Exception error) {
                    SuiOptionPane.showMessageDialog(
                            UtilConsoleGlobals.getActivatedFrame(),
                            error.getMessage());
                    return;
                }

                if (!(((Message)(response.getMessages().elementAt(0))).
                        isFailure())) {
                    if (_certInstInfo.get("crl_action").equals("add") ||
                            _certInstInfo.get("crl_action").equals("replace")) {
                        modified = true;
                    }
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


    public boolean isModified() {
        return modified;
    }

    public CertInfo getCertInfo() {
        return _certInfo;
    }

    Hashtable _certInstInfo = new Hashtable();
    public void show(String filename, String list_type) {
        _filename = filename;
        _listtype = list_type;

        _taskInfo.clear();
        _taskInfo.put("crl_file", filename);
        _taskInfo.put("sie", _sie);
        _taskInfo.put("list_type", list_type);

        try {
            _taskInfo.exec(_taskInfo.SEC_ICRL);
        } catch (Exception error) {
            SuiOptionPane.showMessageDialog(
                    UtilConsoleGlobals.getActivatedFrame(),
                    error.getMessage());
            return;
        }

        if (_taskInfo.getResponse().hasCertInstInfo()) {
            _certInstInfo = _taskInfo.getResponse().getCertInstInfo();
        } else {
            _certInstInfo.put("crl_action", "add");
            _certInstInfo.put("crl_file", filename);
        }
        if (_taskInfo.getResponse().hasCertInfo()) {
            setInfo(_taskInfo.getResponse().getCertInfo());
            super.show();
        } else {
            try {
                MessageDialog.messageDialog( (Message)
                        (_taskInfo.getResponse().getMessages().
                        elementAt(0)));
            } catch (Exception e2) {
                //shouldn't even be here in the first place.  if cgi fail or return nothing
                //then it should be handle right after KeyCertTaskInfo.exec(...) is called
                //If exception occure here here then something is really mess up.
                Debug.println("Error in decoding server messages");
            }
        }
    }

    private void setInfo(CertInfo certInfo) {
        _certInfo = certInfo;
        _crlCertInfoPane.setCertInfo(certInfo);

        try {
            if (((String)(_certInstInfo.get("crl_action"))).equals("add")) {
                bAction.setText(
                        _resource.getString("CRLAddCertDialog", "add"));
            } else {
                bAction.setText(
                        _resource.getString("CRLAddCertDialog", "replace"));
            }
            JButtonFactory.resizeGroup(bHelp, bClose, bAction);
        } catch (Exception e) {
        }
    }

    public CRLAddCertDialog(ConsoleInfo consoleInfo, ResourceSet resource) {
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

        CRLAddCertActionListener listener = new CRLAddCertActionListener();

        bClose = JButtonFactory.createCloseButton(listener);
        GridBagUtil.constrain(mainPane, bClose, 1, 1, 1, 1, 1.0, 0.0,
                GridBagConstraints.SOUTHEAST, GridBagConstraints.NONE,
                0, 0, 0, SuiConstants.COMPONENT_SPACE);


        bAction = JButtonFactory.create("");
        bAction.addActionListener(listener);
        bAction.setActionCommand("ACTION");
        GridBagUtil.constrain(mainPane, bAction, 2, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.SOUTHEAST, GridBagConstraints.NONE,
                0, 0, 0, SuiConstants.SEPARATED_COMPONENT_SPACE);


        bHelp = JButtonFactory.createHelpButton(listener);
        GridBagUtil.constrain(mainPane, bHelp, 3, 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.SOUTHEAST, GridBagConstraints.NONE,
                0, 0, 0, 0);

        setMinimumSize(400, 225);
        setResizable(false);
    }

    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     f.setSize(400,400);
     f.show();

     CRLAddCertDialog d = new CRLAddCertDialog(new ConsoleInfo(), new ResourceSet("com.netscape.admin.certsrv.security.CertManagementResource"), "buddha.txt");
     d.show();
     }*/
}

