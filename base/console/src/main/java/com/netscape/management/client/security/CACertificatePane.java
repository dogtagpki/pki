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
package com.netscape.management.client.security;

import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import com.netscape.management.client.components.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;

class CACertificatePane extends CertificateListPane {

    Table caCertTable;

    ListTableModel tableModel;

    String _sie, _tokenName;
    ConsoleInfo _consoleInfo;
    CertificateDialog _certDialog;

    public void setTokenName(String tokenName) {
        _tokenName = tokenName;
    }

    public CACertificatePane(Vector caCerts,
                             ConsoleInfo consoleInfo,
                             String sie,
                             String tokenName,
                             CertificateDialog certDialog) {
        super(caCerts);

        _certDialog = certDialog;

        this._sie = sie;
        this._tokenName = tokenName;
        this._consoleInfo = consoleInfo;

        Vector columnNames = new Vector();
        columnNames.addElement(resource.getString("CACertificatePane", "certnameLabel"));
        columnNames.addElement(resource.getString("CACertificatePane", "expiredByLabel"));


        tableModel = new ListTableModel(columnNames, null);
        setCertData(caCerts);
        caCertTable = new Table(tableModel, true);
        caCertTable.getSelectionModel().setSelectionMode(DefaultListSelectionModel.SINGLE_SELECTION);

        setContent(caCertTable, resource.getString("CACertificatePane", "tableTitle"),EDITTRUST|INSTALL);

        caCertTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent e) {
                int selected = caCertTable.getSelectedRow();
                if (selected != -1) {
                    detail.setEnabled(true);
                    edittrust.setEnabled(true);
                    delete.setEnabled(true);
                }
            }
        });
        detail.setEnabled(false);
        edittrust.setEnabled(false);
        delete.setEnabled(false);
    }

    public void setCertData(Vector caCerts) {
        Debug.println("CACertificatePane.setCertData");
        setCerts(caCerts);

        Vector rowData = new Vector();
        for (int i=0; i < caCerts.size(); i++) {
            Vector row = new Vector();
            Hashtable cert = (Hashtable)(caCerts.elementAt(i));
            row.addElement(cert.get("NICKNAME"));
            row.addElement(cert.get("AFTERDATE"));
            row.addElement(cert.get("TRUST"));
            rowData.addElement(row);
        }

        tableModel.setRowData(rowData);
        if (caCertTable!=null) {
            caCertTable.setModel(tableModel);
        }
        paintAll(getGraphics());
    }

    public void detailInvoked() {
        String nickname = getSelectedCertNickname(caCertTable,
                                                  resource.getString("CACertificatePane", "certnameLabel"));

        String fingerprint = getSelectedCertAttribute(caCertTable, "FINGERPRINT");

        if (fingerprint.length() != 0) {
            Debug.println("Detail: "+nickname);
            CertificateDetailDialog d = new CertificateDetailDialog(null,
                                            _consoleInfo, 
                                            _sie, 
                                            nickname, fingerprint);
        }
    }

    public void installInvoked() {
        CertInstallWizard certInstallWizard =
            certInstallWizard = new CertInstallWizard(this,  
                                                      _consoleInfo, 
                                                      _sie, 
                                                      _tokenName, 
                                                      CertInstallWizard.CA, null);

        certInstallWizard.setVisible(true);
        _certDialog.refresh();
    }

    public void edittrustInvoked() {
        String nickname = getSelectedCertNickname(caCertTable, 
                                                  resource.getString("CACertificatePane", "certnameLabel"));

        String fingerprint = getSelectedCertAttribute(caCertTable, "FINGERPRINT");

        if (fingerprint.length() != 0) {
            Vector cert = (Vector)(tableModel.getObject(tableModel.getSelectedRow(nickname)));
            Debug.println("Change trust: "+nickname);
            EditTrustDialog trustDialog = new EditTrustDialog(this, 
                                                              _consoleInfo,
                                                              _sie,
                                                              nickname, fingerprint,
                                                               (String)(cert.elementAt(2)));
            trustDialog.setVisible(true);
            cert.setElementAt(Integer.toString(trustDialog.getTrust()), 2);
        }
    }

    public void deleteInvoked() {
        String nickname = getSelectedCertNickname(caCertTable, 
                                                  resource.getString("CACertificatePane", "certnameLabel"));

        String fingerprint = getSelectedCertAttribute(caCertTable, "FINGERPRINT");

        if (fingerprint.length() != 0) {
            if (true == confirmDeleteDialog(nickname)) {
                Debug.println("Delete: "+nickname);
                if (KeyCertUtility.deleteCert(this, _consoleInfo,
                                              _sie, 
                                              nickname, fingerprint)) {
                    tableModel.deleteRow(nickname);
                    caCertTable.clearSelection();
                    caCertTable.repaint();
                }
            }
        }
    }

    public void helpInvoked() {
        help.contextHelp("CACertificatePane", "help");
    }
}
