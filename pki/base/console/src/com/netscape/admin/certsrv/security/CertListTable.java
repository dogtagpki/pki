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


import com.netscape.management.client.console.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

import java.util.*;
import java.awt.*;
import java.awt.event.*;

import javax.swing.*;
import javax.swing.table.*;
import javax.swing.event.*;

//import crysec.SSL.DBManager;
//import crysec.X509;
//import crysec.X500Name;
//import crysec.Utils;

class CertListTable extends JPanel implements MouseListener, Runnable {
    JTable _table;
    CertListTableModel _dataModel;
    KeyCertTaskInfo _taskInfo;

    String alias;
    String _certName;
    boolean local = false;
    boolean setupComplete;
    Vector certList;
 //   DBManager trustdb;

    //IBackgroundLoaderCallback _callback;

    ConsoleInfo _consoleInfo;

    private String formatLineString(String val, String option,
            boolean newLine) {
        if (val != null) {
            return val + (newLine ? option + "\n":option);
        } else {
            return "";
        }
    }

    public void showCert() {
// to get it compile
/*
        int row = _table.getSelectedRow();
        if (row == -1)
            return;

        //show cert here

        if (local) {
            X509 cert = (X509)(certList.elementAt(row));
            X500Name holder = (X500Name)(cert.getHolder());
            X500Name issuer = (X500Name)(cert.getIssuer());

            StringBuffer subjectString = new StringBuffer();
            StringBuffer issuerString = new StringBuffer();

            subjectString.append(
                    formatLineString(holder.getName(), "", true));
            subjectString.append(
                    formatLineString(holder.getEmail(), "", true));
            subjectString.append(
                    formatLineString(holder.getOrganizationName(), "",
                    true));
            subjectString.append(
                    formatLineString(holder.getOrgUnitName(), "", true));
            subjectString.append(
                    formatLineString(holder.getLocalityName(), "", true));
            subjectString.append(
                    formatLineString(holder.getStateName(), ", ",
                    false) + holder.getCountryName());

            issuerString.append(
                    formatLineString(issuer.getName(), "", true));
            issuerString.append(
                    formatLineString(issuer.getEmail(), "", true));
            issuerString.append(
                    formatLineString(issuer.getOrganizationName(), "",
                    true));
            issuerString.append(
                    formatLineString(issuer.getOrgUnitName(), "", true));
            issuerString.append(
                    formatLineString(issuer.getLocalityName(), "", true));
            issuerString.append(
                    formatLineString(issuer.getStateName(), ", ",
                    false) + issuer.getCountryName());

            CertInfo ci = new CertInfo(holder.getName(),
                    issuerString.toString(), subjectString.toString(),
                    "", "", cert.getNotBeforeDate().toString(),
                    cert.getNotAfterDate().toString(),
                    new String(cert.getFingerprint()), "1", "0",
                    holder.getOrganizationName());

            CertInfoDialog infoDialog = new CertInfoDialog(null, ci);
            infoDialog.show();

            if (CertInfoDialog.delete) {
                deleteRow(row);

                trustdb.remove(Utils.toHexString(cert.getFingerprint()));
               trustdb.save();
            }
        } else {
            _taskInfo.clear();
            _taskInfo.put("certnn", getRow(row).getCertName());
            _taskInfo.put("alias", alias);
            Response response = null;
            try {
                response = _taskInfo.exec(_taskInfo.SEC_ECRT);
            } catch (Exception e) {
                SuiOptionPane.showMessageDialog(
                        UtilConsoleGlobals.getActivatedFrame(),
                        e.getMessage());
                return;
            }

            if (response.hasCertInfo()) {
                CertInfoDialog infoDialog =
                        new CertInfoDialog(null,
                        response.getCertInfo(), _taskInfo);
                ModalDialogUtil.setDialogLocation(infoDialog, this);
                infoDialog.show();
                //since CertInfoDialog is a modal dialog we will wait until it comes back to check wheather the cer
                //has been deleted if it is deleted then we need to refresh the table
                if (CertInfoDialog.delete) {
                    deleteRow(row);
                }
            }

            //MessageDialog.messageDialog((Message)(response.getMessages().elementAt(0)));
        }
 */
    }


    public void mouseClicked(MouseEvent e) {
        int row = _table.rowAtPoint(e.getPoint());

        if (e.getClickCount() < 2)
            return;

        if (row == -1) {
            _table.clearSelection();
        } else {
            showCert();
        }
    }

    public void mouseEntered(MouseEvent e) {}
    public void mouseExited(MouseEvent e) {}
    public void mousePressed(MouseEvent e) {}
    public void mouseReleased(MouseEvent e) {}

    public boolean isTableSetup() {
        return setupComplete;
    }


    public CertListTable() {
        super(true);
        local = true;

        setLayout(new BorderLayout());

        setupComplete = true;

      //  trustdb = new DBManager();
     //   Enumeration e = trustdb.elements();
       Enumeration e = null;
        certList = new Vector();
        Vector v = new Vector();
      //  while (e.hasMoreElements()) {
    //        X509 cert = (X509)(e.nextElement());
   //         certList.addElement(cert);
//            v.addElement(
 //                   new CertBasicInfo(cert.getHolder().getName(), "Trust Server Certificate",
                 //   cert.getNotAfterDate().toString()));
       // }

        _dataModel = new CertListTableModel(
                CertBasicInfo.getCertTitleLabels(), v);
        setupTable(_dataModel);
    }


    public CertListTable(String certName, ConsoleInfo consoleInfo/*, IBackgroundLoaderCallback callback*/) {
        super(true);
        _consoleInfo = consoleInfo;
        _certName = certName;
        //_callback    = callback;
        setLayout(new BorderLayout());

        setupComplete = true;

        run();

        /*setBackground( Color.white );*/
    }



    private void setupTable(CertListTableModel _tableModel) {
        // Create the table
        _table = new SuiTable(_tableModel);
        _table.addMouseListener(this);
        _table.setColumnSelectionAllowed(false);
        /*_table.setMultipleSelectionAllowed(false);*/

        // Put the table and header into a scrollPane
        JScrollPane scrollpane = new JScrollPane();
        JTableHeader tableHeader = _table.getTableHeader();

        // create and add the column heading to the scrollpane's
        // column header viewport
        JViewport headerViewport = new JViewport();
        headerViewport.setLayout(
                new BoxLayout(headerViewport, BoxLayout.X_AXIS));
        headerViewport.add(tableHeader);
        scrollpane.setColumnHeader(headerViewport);

        // add the table to the viewport
        JViewport mainViewPort = scrollpane.getViewport();
        mainViewPort.add(_table);

        // speed up resizing repaints by turning off live cell updates
        tableHeader.setUpdateTableInRealTime(false);

        add("Center", scrollpane);

        setPreferredSize(new Dimension(0, 0));
        //_callback.classLoaded(this, "CertListTable");
    }

    //public void setCertList(String certName) {
    public void run() {

        _taskInfo = new KeyCertTaskInfo(_consoleInfo);
        _dataModel = new CertListTableModel(
                CertBasicInfo.getCertTitleLabels(), new Vector());
        //setCertList(certName);

        //_dataModel.deleteAllRows();
        //call cgi here to get the cert information
        _taskInfo.put("alias", _certName);
        alias = _certName;
        Response response = null;
        try {
            response = _taskInfo.exec(_taskInfo.SEC_MGCRT);
        } catch (Exception e) {
            SuiOptionPane.showMessageDialog(
                    UtilConsoleGlobals.getActivatedFrame(), e.getMessage());
            setupComplete = false;
            return;
        }

        if (response.hasCertList()) {
            _dataModel.setRowData(response.getCertList());
            //repaint();
        }

        setupTable(_dataModel);
    }

    /**
      *
      *  @return LDAPEntry at specified index, null if index > number of rows
      *
      */
    public CertBasicInfo getRow(int index) {
        return _dataModel.getRow(index);
    }

    /**
      *
      *  @return the number of rows in the table.
      *
      */
    public int getRowCount() {
        return _dataModel.getRowCount();
    }

    /**
      *
      *  Removes the first occurrence of the LDAPEntry from this table. If the object is found.
      *
      *  @param ldapEntry   LDAPEntry to delete from this table.
      *
      */
    public void deleteRow(int rowIndex) {
        _dataModel.deleteRow(rowIndex);
        repaint();
    }
}
