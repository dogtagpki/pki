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
import java.awt.*;
import java.util.*;
import javax.swing.*;
import javax.swing.event.*;
import java.net.*;

import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;
import com.netscape.management.client.components.*;

class CRLCertificatePane extends CertificateListPane {

    Table crlCertTable;
    private JTabbedPane infoPane = new JTabbedPane();

    ListTableModel tableModel;

    String _sie;
    ConsoleInfo _consoleInfo;
    CertificateDialog _certDialog;

     public CRLCertificatePane(Vector crlCerts, ConsoleInfo consoleInfo, String sie, CertificateDialog certDialog) {
        super(crlCerts);

        _certDialog = certDialog;

        resource = new ResourceSet("com.netscape.management.client.security.securityResource");

        this._sie = sie;
        this._consoleInfo = consoleInfo;

        Vector columnNames = new Vector();
        columnNames.addElement(resource.getString("CRLCertificatePane", "issuedByLabel"));
        columnNames.addElement(resource.getString("CRLCertificatePane", "effectiveDateLabel"));
        columnNames.addElement(resource.getString("CRLCertificatePane", "nextUpdateLabel"));
        columnNames.addElement(resource.getString("CRLCertificatePane", "typeLabel"));

        tableModel = new ListTableModel(columnNames, null);
        setCertData(crlCerts);
        crlCertTable = new Table(tableModel, true);
        crlCertTable.getSelectionModel().setSelectionMode(DefaultListSelectionModel.SINGLE_SELECTION);

        setContent(crlCertTable, resource.getString("CRLCertificatePane", "tableTitle"), ADD);

        crlCertTable.getSelectionModel().addListSelectionListener(new ListSelectionListener() {
            public void valueChanged(ListSelectionEvent e) {
                int selected = crlCertTable.getSelectedRow();
                if (selected != -1) {
                    detail.setEnabled(true);
                    delete.setEnabled(true);
                }
            }
        });

        detail.setEnabled(false);
        delete.setEnabled(false);
    }

    public void setCertData(Vector crlCerts) {
        Debug.println("CRLCertificatePane.setCertData");
        setCerts(crlCerts);
        
        Vector rowData = new Vector();
        for (int i=0; i < crlCerts.size(); i++) {
            Vector row = new Vector();
            Hashtable cert = (Hashtable)(crlCerts.elementAt(i));
            //row.addElement(((Hashtable)(cert.get("ISSUER"))).get("O"));
            row.addElement(cert.get("NAME"));
            row.addElement(cert.get("LAST_UPDATE"));
            row.addElement(cert.get("NEXT_UPDATE"));
            row.addElement(cert.get("TYPE"));
            rowData.addElement(row);
        }

        tableModel.setRowData(rowData);
        if (crlCertTable!=null) {
            crlCertTable.setModel(tableModel);
        }

        paintAll(getGraphics());
    }

    public void detailInvoked() {

        String nickname = getSelectedCertNickname(crlCertTable,
                          resource.getString("CRLCertificatePane", "issuedByLabel"));


        if (nickname.length() != 0) {
            try {
                Hashtable args = new Hashtable();
                args.put("formop", "FIND_CRL_CKL");
                args.put("sie", _sie);
                args.put("crlname", nickname);
                args.put("list_type", getSelectedCertNickname(crlCertTable,
                                                              resource.getString("CRLCertificatePane", "typeLabel")));

                Debug.println(args.toString());
                AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
                                                      "admin-serv/tasks/configuration/SecurityOp"),
                                              _consoleInfo.getAuthenticationDN(),
                                              _consoleInfo.getAuthenticationPassword());

                admTask.setArguments(args);

                admTask.exec();
                Debug.println(admTask.getResultString().toString());
            
                if (!SecurityUtil.showError(admTask)) {
                    CertificateList certList = new CertificateList(admTask.getResultString().toString());
                    Hashtable cert = null;
                    if (certList.getCRLCerts().size()!=0) {
                        cert = (Hashtable)(certList.getCRLCerts().elementAt(0));

                        (new RevocationListDialog(cert)).setVisible(true);
                    }
                } 
            } catch (Exception e) {
                if (Debug.isEnabled()) {
                    e.printStackTrace();
                }
                Debug.println(e.toString());
            }
        }
    }

    class RevocationListDialog extends AbstractDialog {
        public RevocationListDialog(Hashtable cert) {
            super(null, 
                  CRLCertificatePane.this.resource.getString("CertificateDetailDialog", "title"),
                  true,
                  OK|HELP);

            CertificateInfoPanels certInfoPane = new CertificateInfoPanels(cert);

        infoPane.removeAll();
            infoPane.add(CRLCertificatePane.this.resource.getString("CertificateDetailDialog", "generalTitle"), certInfoPane.getDetailInfo());
            infoPane.add(CRLCertificatePane.this.resource.getString("CertificateDetailDialog", "revocationList"), certInfoPane.getRevocationList());

            getContentPane().setLayout(new GridBagLayout());
            GridBagUtil.constrain(getContentPane(), infoPane,
                                  0, 0, 1, 1,
                                  1.0, 1.0,
                                  GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                                  0, 0, 0, 0);


            pack();
        }

        public void helpInvoked() {
            Help help = new Help(CRLCertificatePane.this.resource);
            help.contextHelp("CertificateDetailDialog_CRL", "help");
        }
    }

    public void addInvoked() {
        InstallCRLDialog d = new InstallCRLDialog(this  , _consoleInfo, _sie);
        d.show();

        _certDialog.refresh();
    }

    public void deleteInvoked() {
        String nickname = getSelectedCertNickname(crlCertTable,
                          resource.getString("CRLCertificatePane", "issuedByLabel"));


        if (nickname.length() != 0) {
            if (true == confirmDeleteDialog(nickname)) {
                try {
                    Hashtable args = new Hashtable();
                    args.put("formop", "DELETE_CRL_CKL");
                    args.put("sie", _sie);
                    args.put("crlname", nickname);
                    args.put("list_type", getSelectedCertNickname(crlCertTable,
                                                                  resource.getString("CRLCertificatePane", "typeLabel")));


                    AdmTask admTask = new AdmTask(new URL(_consoleInfo.getAdminURL() +
                                                          "admin-serv/tasks/configuration/SecurityOp"),
                                                  _consoleInfo.getAuthenticationDN(),
                                                  _consoleInfo.getAuthenticationPassword());

                    admTask.setArguments(args);

                    admTask.exec();
            
                    if (!SecurityUtil.showError(admTask)) {
                        tableModel.deleteRow(nickname);
                        crlCertTable.clearSelection();
                        crlCertTable.repaint();
                    }
                } catch (Exception e) {
                    Debug.println(e.toString());
                }
            }
        }
    }

    public void helpInvoked() {
        help.contextHelp("CRLCertificatePane", "help");
    }

}
