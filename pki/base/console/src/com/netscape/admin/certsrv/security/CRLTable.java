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
import com.netscape.management.nmclf.*;

import javax.swing.*;
import javax.swing.table.*;

import java.awt.event.*;
import java.util.*;
import java.io.*;
import java.awt.*;


class CRLTable extends JPanel implements MouseListener {

    ResourceSet _resource;
    KeyCertTaskInfo _taskInfo;
    String _sie;
    ConsoleInfo _consoleInfo;

    CRLDeleteCertDialog _crlDeleteCertDialog = null;

    String startCRL = "-----BEGIN CRL LIST-----";
    String endCRL = "-----END CRL LIST-----";
    String startCKL = "-----BEGIN CKL LIST-----";
    String endCKL = "-----END CKL LIST-----";

    String certName;
    boolean setupComplete;

    private Vector getRowData(String data) {
        Vector rowData = new Vector();
        BufferedReader stream = new BufferedReader(new StringReader(data));

        // First, read CRL's
        try {
            while (!(stream.readLine().equals(startCRL))) {
            }

            String line;
            while (!((line = stream.readLine()).equals(endCRL))) {
                StringTokenizer token =
                        new StringTokenizer(line, ";", false);
                Vector row = new Vector();
                //get cert name and expire date and setup a row
                row.addElement(token.nextToken());
                row.addElement(token.nextToken());
                row.addElement((String)"CRL");
                rowData.addElement(row);
            }
        } catch (IOException e) { /*error message here */
        }

        // Next, read CKL's
        try {
            while (!(stream.readLine().equals(startCKL))) {
            }

            String line;
            while (!((line = stream.readLine()).equals(endCKL))) {
                StringTokenizer token =
                        new StringTokenizer(line, ";", false);
                Vector row = new Vector();
                //get cert name and expire date and setup a row
                row.addElement(token.nextToken());
                row.addElement(token.nextToken());
                row.addElement((String)"CKL");
                rowData.addElement(row);
            }
        } catch (IOException e) { /*error message here */
        }

        return rowData;
    }

    private Vector getColumnHeader() {
        Vector column = new Vector();
        column.addElement(_resource.getString("CRLTable", "column1"));
        column.addElement(_resource.getString("CRLTable", "column2"));
        column.addElement(_resource.getString("CRLTable", "column3"));
        return column;
    }

    public void showCert() {
        if (_crlTable.getSelectedRow() != -1) {
            _crlDeleteCertDialog.show( (String)
                    (_crlTable.getValueAt(_crlTable.getSelectedRow(),
                    0)), (String)
                    (_crlTable.getValueAt(_crlTable.getSelectedRow(), 2)));
            if (_crlDeleteCertDialog.isDeleted()) {
                _crlTableModel.deleteRow(_crlTable.getSelectedRow());
                repaint();
            }
        }

    }

    JTable _crlTable;
    public void mouseClicked(MouseEvent e) {
        int row = _crlTable.rowAtPoint(e.getPoint());

        if (e.getClickCount() < 2)
            return;
        if (row == -1) {
            _crlTable.clearSelection();
        } else {
            showCert();
        }
    }
    public void mouseEntered(MouseEvent e) { }
    public void mouseExited(MouseEvent e) { }
    public void mousePressed(MouseEvent e) { }
    public void mouseReleased(MouseEvent e) { }


    public void update() {
        _taskInfo = new KeyCertTaskInfo(_consoleInfo);
        _sie = KeyCertUtility.createTokenName(_consoleInfo);
        _crlDeleteCertDialog =
                new CRLDeleteCertDialog(_consoleInfo, _resource);

        _taskInfo.put("sie", _sie);
        try {
            _taskInfo.exec(_taskInfo.SEC_MGCRL);
        } catch (Exception e) {
            SuiOptionPane.showMessageDialog(
                    UtilConsoleGlobals.getActivatedFrame(), e.getMessage());
            setupComplete = false;
            return;
        }

        if (_crlTableModel == null) {
            _crlTableModel = new CRLTableModel( getRowData(
                    _taskInfo.getResponse().getServerResponse()),
                    getColumnHeader());
        } else {
            _crlTableModel.update( getRowData(
                    _taskInfo.getResponse().getServerResponse()),
                    getColumnHeader());
        }

    }

    public CRLTable(ConsoleInfo consoleInfo, ResourceSet resource) {
        setLayout(new BorderLayout());

        setupComplete = true;

        _resource = resource;
        _consoleInfo = consoleInfo;

        update();

        _crlTable = new SuiTable();
        //_crlTableModel = new CRLTableModel(getRowData(_taskInfo.getResponse().getServerResponse()), getColumnHeader());
        _crlTable.setModel(_crlTableModel);
        _crlTable.setAutoResizeMode(_crlTable.AUTO_RESIZE_ALL_COLUMNS);
        _crlTable.addMouseListener(this);
        //_crlTable.setMultipleSelectionAllowed(false);
        _crlTable.getSelectionModel().setSelectionMode(
                DefaultListSelectionModel.SINGLE_SELECTION);
        //_crlTable.setSelectionModel(new DefaultSingleSelectionModel());


        // Put the table and header into a scrollPane
        JScrollPane scrollPane = new JScrollPane(
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        JTableHeader tableHeader = _crlTable.getTableHeader();

        // create and add the column heading to the scrollpane's
        // column header viewport
        JViewport headerViewport = new JViewport();
        headerViewport.setLayout(new BorderLayout()/*new BoxLayout(headerViewport, BoxLayout.X_AXIS)*/);
        headerViewport.add(tableHeader);
        scrollPane.setColumnHeader(headerViewport);

        // add the table to the viewport
        JViewport mainViewPort = scrollPane.getViewport();
        mainViewPort.add(_crlTable);

        // speed up resizing repaints by turning off live cell updates
        tableHeader.setUpdateTableInRealTime(false);

        add(scrollPane);

    }

    CRLTableModel _crlTableModel;

    public void repaint() {
        _crlTable.validate();
        _crlTable.repaint();
        super.repaint();
    }

    public void addCert(String issuer, String expires, String type) {
        _crlTableModel.addRow(issuer, expires, type);
        repaint();
    }

    public boolean isTableSetup() {
        return setupComplete;

    }

    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     //f.setSize(400,400);
     ResourceSet resource = new ResourceSet("com.netscape.admin.certsrv.security.CertManagementResource");
     f.getContentPane().add(new CRLTable(new ConsoleInfo(), resource));
     f.pack();
     f.show();
     }*/
}

