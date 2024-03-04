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
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.components.*;

class ServerCertificatePane extends CertificateListPane {

    Table serverCertTable;

    ListTableModel tableModel;

    String _sie, _tokenName;
    ConsoleInfo _consoleInfo;
    CertificateDialog _certDialog;

    public void setTokenName(String tokenName) {
        _tokenName = tokenName;
    }

    public ServerCertificatePane(Vector serverCerts, ConsoleInfo consoleInfo, String sie, String tokenName, CertificateDialog certDialog) {
        super(serverCerts);

        _certDialog = certDialog;

        this._sie = sie;
        this._tokenName = tokenName;
        this._consoleInfo = consoleInfo;

        Vector columnNames = new Vector();
        columnNames.addElement(resource.getString("ServerCertificatePane", "nameLabel"));
        columnNames.addElement(resource.getString("ServerCertificatePane", "issuedToLabel"));
        columnNames.addElement(resource.getString("ServerCertificatePane", "issuedByLabel"));
        columnNames.addElement(resource.getString("ServerCertificatePane", "expiredByLabel"));


        tableModel = new ListTableModel(columnNames, null);
        setCertData(serverCerts);

        serverCertTable = new Table(tableModel, true);
        serverCertTable.getSelectionModel().setSelectionMode(DefaultListSelectionModel.SINGLE_SELECTION);

        setContent(serverCertTable, resource.getString("ServerCertificatePane", "tableTitle"),REQUEST|RENEW|INSTALL);

        serverCertTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent e) {
                int selected = serverCertTable.getSelectedRow();
                if (selected != -1) {
                    detail.setEnabled(true);
                    renew.setEnabled(true);
                    delete.setEnabled(true);
                } 
            }
        });
        detail.setEnabled(false);
        renew.setEnabled(false);
        delete.setEnabled(false);
    }

    public void setCertData(Vector serverCerts) {
        Debug.println("ServerCertificatePane.setCertData");
        setCerts(serverCerts);

        Vector rowData = new Vector();
        for (int i=0; i < serverCerts.size(); i++) {
            Vector row = new Vector();
            Hashtable cert = (Hashtable)(serverCerts.elementAt(i));
            row.addElement(cert.get("NICKNAME"));
            row.addElement(((Hashtable)(cert.get("SUBJECT"))).get("CN"));
            row.addElement(((Hashtable)(cert.get("ISSUER"))).get("CN"));
            row.addElement(cert.get("AFTERDATE"));
            rowData.addElement(row);
        }

        tableModel.setRowData(rowData);
        if (serverCertTable!=null) {
            serverCertTable.setModel(tableModel);
        }
        paintAll(getGraphics());
    }

    public void detailInvoked() {
        String nickname = getSelectedCertNickname(serverCertTable, 
                                                  resource.getString("ServerCertificatePane", "nameLabel"));

        String fingerprint = getSelectedCertAttribute(serverCertTable, "FINGERPRINT");

        if (fingerprint.length() != 0) {
            _certDialog.setBusyCursor(true);        
            CertificateDetailDialog d = new CertificateDetailDialog(null,
                                            _consoleInfo, 
                                            _sie, 
                                            nickname, fingerprint);
            _certDialog.setBusyCursor(false);
        }
    }

    public void requestInvoked() {
        CertRequestWizard certRequestWizard =
            certRequestWizard = new CertRequestWizard(this, 
                                                      _consoleInfo, 
                                                      _sie,
                                                      _tokenName);
        certRequestWizard.setVisible(true);
    }

    public void renewInvoked() {
        CertRequestWizard certRequestWizard =
            certRequestWizard = new CertRequestWizard(this, 
                                                      _consoleInfo, 
                                                      _sie, 
                                                      _tokenName);

        certRequestWizard.setVisible(true);
    }

    public void installInvoked() {
        CertInstallWizard certInstallWizard = 
            certInstallWizard = new CertInstallWizard(this,  
                                                      _consoleInfo, 
                                                      _sie, 
                                                      _tokenName, 
                                                      CertInstallWizard.SERVER, getCerts());

        certInstallWizard.setVisible(true);
        _certDialog.refresh();
    }


    public void deleteInvoked() {
        String nickname = getSelectedCertNickname(serverCertTable,
                                                  resource.getString("ServerCertificatePane", "nameLabel"));

        String fingerprint = getSelectedCertAttribute(serverCertTable, "FINGERPRINT");

        if (fingerprint.length() != 0) {
            if (true == confirmDeleteDialog(nickname)) {
                _certDialog.setBusyCursor(true);
                if (KeyCertUtility.deleteCert(this, _consoleInfo,
                                              _sie, 
                                              nickname, fingerprint)) {
                    tableModel.deleteRow(nickname);
                    serverCertTable.clearSelection();
                    serverCertTable.repaint();
                }
                _certDialog.refresh();
                _certDialog.setBusyCursor(false);
            }
        }
    }

    public void helpInvoked() {
        help.contextHelp("ServerCertificatePane", "help");
    }
}