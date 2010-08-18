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
package com.netscape.admin.certsrv.config;

import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.ug.*;
import javax.swing.*;
import javax.swing.event.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.console.*;
import com.netscape.certsrv.common.*;
import com.netscape.admin.certsrv.keycert.*;

/**
 * CA certs Tab
 *
 * @author Christine Ho 
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class CACertsTab extends CMSBaseUGTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANEL_NAME = "CACERTS";
    private CMSBaseResourceModel mModel;
    private AdminConnection mConnection;
    private String mDestination;
    private ConsoleInfo mConsoleInfo;
    
    protected JScrollPane mScrollPane;
    protected JTable mTable;                    //table
    protected ListCertsModel mDataModel;   //table model
    protected CertViewDialog mEditor=null;      //keep single copy
    
    protected JButton mRefresh, mAdd, mDelete, mView, mEdit, mHelp;
    private final static String HELPINDEX = "configuration-log-plugin-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public CACertsTab(CMSBaseResourceModel model, String destination) {
        super(PANEL_NAME, model);
        mConnection = model.getServerInfo().getAdmin();
        mModel = model;
        mConsoleInfo = mModel.getConsoleInfo();
        mDataModel = new ListCertsModel();
        mDestination = destination;
        mHelpToken = HELPINDEX;
    }

    /*==========================================================
     * public methods
     *==========================================================*/


    /*==========================================================
     * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mRefresh)) {
            refresh();
        }
        if (e.getSource().equals(mHelp)) {
            helpCallback();
        }
        if (e.getSource().equals(mAdd)) {

            CertSetupWizardInfo info = new CertSetupWizardInfo(mConnection, mConsoleInfo);

            // if it is "0", then it means it is root cert mode.
            // if it is "1", then it means it is user cert mode.
            info.setMode("0");
            CertSetupWizard wizard = new CertSetupWizard(
              mModel, info);
            refresh();
            return;
        }

        int row = mTable.getSelectedRow();
        if(row < 0)
            return;

        if (e.getSource().equals(mDelete)) {
            Debug.println("Delete");
            if(mTable.getSelectedRow()< 0)
                return;
            int i = showConfirmDialog("DELETE");
            if (i == JOptionPane.YES_OPTION) {
                delete();
                Debug.println("Deleted");
            }
        }
        if (e.getSource().equals(mView)) {
            Debug.println("View");
            String nickname = (String)(mTable.getValueAt(row, 3)) + ":" +
              (String)(mTable.getValueAt(row, 0));
            String serialno = (String)(mTable.getValueAt(row, 1));
            String issuername = (String)(mTable.getValueAt(row, 2));

            try {
                NameValuePairs nvps = new NameValuePairs();
                nvps.add(Constants.PR_NICK_NAME, nickname);
                nvps.add(Constants.PR_SERIAL_NUMBER, serialno);
                nvps.add(Constants.PR_ISSUER_NAME, issuername);
                NameValuePairs results = mConnection.process(
                  DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_CERT_PRETTY_PRINT,
                  Constants.RS_ID_CONFIG, nvps);
                if (nvps.size() <= 0)
                    return;
                NameValuePair nvp = results.elementAt(0);
                String name = nvp.getName();
                String print = nvp.getValue();
                CertViewDialog certdialog = new CertViewDialog(mModel.getFrame());
                certdialog.showDialog(nickname, print);
            } catch (EAdminException ex) {
                CMSAdminUtil.showErrorDialog(mModel.getFrame(), mResource, ex.toString(),
                  CMSAdminUtil.ERROR_MESSAGE);
            }
        }
        if (e.getSource().equals(mEdit)) {
            Debug.println("Edit");
            String nickname = (String)(mTable.getValueAt(row, 3)) + ":" +
              (String)(mTable.getValueAt(row, 0));
            String serialno = (String)(mTable.getValueAt(row, 1));
            String issuername = (String)(mTable.getValueAt(row, 2));

            try {
                NameValuePairs nvps = new NameValuePairs();
                nvps.add(Constants.PR_NICK_NAME, nickname);
                nvps.add(Constants.PR_SERIAL_NUMBER, serialno);
                nvps.add(Constants.PR_ISSUER_NAME, issuername);
                NameValuePairs results = mConnection.process(
                  DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_ROOTCERT_TRUSTBIT,
                  Constants.RS_ID_CONFIG, nvps);
                if (nvps.size() <= 0)
                    return;
                NameValuePair nvp = results.elementAt(0);
                String name = nvp.getName();
                String trust = nvp.getValue();
                int i;
                String[] params = new String[2];
                if (trust.equals("U")) {
                    params[0] = "untrusted";
                    params[1] = "trust"; 
                    i = showConfirmDialog("TRUST", params);
                } else {
                    params[0] = "trusted";
                    params[1] = "untrust"; 
                    i = showConfirmDialog("TRUST", params);
                }

                if (i == JOptionPane.YES_OPTION) {
                    nvps.add("trustbit", params[1]);
                    mConnection.modify(DestDef.DEST_SERVER_ADMIN, 
                      ScopeDef.SC_ROOTCERT_TRUSTBIT,
                      Constants.RS_ID_CONFIG, nvps);
                }
            } catch (EAdminException ex) {
                CMSAdminUtil.showErrorDialog(mModel.getFrame(), mResource, ex.toString(),
                  CMSAdminUtil.ERROR_MESSAGE);
            }
        }
    }

    //==== MOUSELISTENER ======================
    public void mouseClicked(MouseEvent e) {
        setButtons();
    }

    public void mouseReleased(MouseEvent e) {
        setButtons();    
    }

    /*==========================================================
     * protected methods
     *==========================================================*/
    public void refresh() {

        mDataModel.removeAllRows();
        update();       
        
        setButtons();
        mTable.invalidate();
        mTable.validate();
        mTable.repaint(1);
    }

    /**
     * create the user action button panel
     */
    protected JPanel createButtonPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mAdd = makeJButton("ADD");
        mDelete = makeJButton("DELETE");
        mView = makeJButton("VIEW");
        mEdit = makeJButton("EDIT");
        JButton[] buttons = {mAdd, mDelete, mView, mEdit};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

    protected JPanel createActionPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
        JButton[] buttons = { mRefresh, mHelp };
        return makeJButtonPanel(buttons, true);
    }

    protected JPanel createListPanel() {
        mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);

        //center table
        mTable = new JTable(mDataModel);
        mScrollPane = JTable.createScrollPaneForTable(mTable);
        //mScrollPane.setBorder(CMSAdminUtil.makeTitledBorder(mResource,PANEL_NAME,"USERS"));
        mScrollPane.setHorizontalScrollBarPolicy(mScrollPane.HORIZONTAL_SCROLLBAR_ALWAYS);
        mScrollPane.setVerticalScrollBarPolicy(mScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setAutoscrolls(true);
        mTable.sizeColumnsToFit(true);
        mTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        mTable.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        mTable.addMouseListener(this);
        setLabelCellRenderer(mTable,0);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
      gbc.fill = gbc.BOTH;
        gbc.gridwidth = 1;
        gbc.weightx = 1.0;
        gbc.insets = EMPTY_INSETS;
        gb.setConstraints(mScrollPane, gbc);
        mListPanel.add(mScrollPane);

        JPanel buttonPanel = createButtonPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        gbc.insets = EMPTY_INSETS;
        gb.setConstraints(buttonPanel, gbc);
        mListPanel.add(buttonPanel);

        refresh();

        return mListPanel;
    }

    //Set the first column's cellrender as label cell
    protected void setLabelCellRenderer(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(new LabelCellRenderer(new JLabel()));
    }


    //set buttons
    private void setButtons() {
        
        //enable and diable buttons accordingly
        //Debug.println("setButtons() - "+mTable.getSelectedRow());
        //Debug.println("setButtons() - "+mTable.getSelectionModel().isSelectionEmpty());
        if (mTable.getSelectionModel().isSelectionEmpty()) {
            mDelete.setEnabled(false);
            mView.setEnabled(false);
            return;
        }
        
        if(mDataModel.getRowCount()<=0) {
            mDelete.setEnabled(false);
            mView.setEnabled(false);
            return;
        }
        
        mDelete.setEnabled(true);
        mView.setEnabled(true);        
        
    }
    
    //=============================================
    // SEND REQUESTS TO THE SERVER SIDE
    //=============================================
    private void update() {
        //send request and parse data
        
        mModel.progressStart();
        NameValuePairs response;
        try {
            response = mConnection.search(mDestination, ScopeDef.SC_ROOTCERTSLIST, 
              new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }

        Debug.println(response.toString());

        //parse the data
        mDataModel.removeAllRows();
        if (response != null) {
            String[] vals = new String[response.size()];
            int i=0;
            for (Enumeration e = response.getNames(); e.hasMoreElements() ;) {
                String entry = ((String)e.nextElement()).trim();
                vals[i++] = entry;
            }

            int sindex = 0;
            String snickname = "";
            CMSAdminUtil.quickSort(vals, 0, response.size()-1);
            for (i=0; i<vals.length; i++) {
                Vector v = new Vector();
                String entry = vals[i];
                String value = response.getValue(entry);

                // look for the comma separator
                int lastindex = entry.lastIndexOf(",");
                if (lastindex != -1) {
                    String nickname = entry.substring(0, lastindex);
                    int colonindex = nickname.indexOf(":");
                    if (colonindex != -1)
                        v.addElement(nickname.substring(colonindex+1));
                    else
                        v.addElement(nickname);
                    v.addElement(entry.substring(lastindex+1));
                    v.addElement(value);
                    if (colonindex != -1)
                        v.addElement(nickname.substring(0, colonindex));
                    else
                        v.addElement("internal");
                    mDataModel.addRow(v);
                }
            }
            if (vals.length > 0)
                mTable.setRowSelectionInterval(0,0);
        }

        mModel.progressStop();
    }

    private void delete() {
        mModel.progressStart();
        int row = mTable.getSelectedRow();
        String nickname = (String)(mDataModel.getValueAt(row, 3))+":"+
          (String)(mDataModel.getValueAt(row, 0));
        String id = nickname+":SERIAL#<"+mDataModel.getValueAt(row, 1)+">"
          +mDataModel.getValueAt(row, 2);

        //send comment to server for the removal of user
        try {
            mConnection.delete(mDestination, ScopeDef.SC_ROOTCERTSLIST, id);
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }
        mModel.progressStop();
        //send comment to server and refetch the content
        refresh();
    }

}
