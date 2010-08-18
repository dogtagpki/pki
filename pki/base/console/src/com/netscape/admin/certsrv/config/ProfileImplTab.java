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
import com.netscape.certsrv.common.*;

/**
 * Policy Instances Management Tab
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class ProfileImplTab extends CMSBaseUGTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String IMPL_NAME = ProfileImplDataModel.IMPL_NAME;
    private static final String IMPL_TYPE = ProfileImplDataModel.IMPL_TYPE;
    private static final String IMPL_CLASS = ProfileImplDataModel.IMPL_CLASS;
    private static final String IMPL_DESC = ProfileImplDataModel.IMPL_DESC;
    
    private static final String PANEL_NAME = "PROFILEIMPL";
    private static final String DIALOG_PREFIX = "PROFILEREGISTERDIALOG";
  
    private AdminConnection mConnection;
    private String mDestination;
    
    protected JScrollPane mScrollPane;
    protected JTable mTable;                    //table
    protected ProfileImplDataModel mDataModel;   //table model
    protected ProfileRegisterDialog mEditor=null;      //keep single copy
    protected ViewDialog mViewer=null;      //keep single copy
    
    protected JButton mRefresh, mAdd, mDelete, mView, mHelp;
    private final static String HELPINDEX = "configuration-certificateprofiles";

    /*==========================================================
     * constructors
     *==========================================================*/
    public ProfileImplTab(CMSBaseResourceModel model, String destination) {
        super(PANEL_NAME, model);
        mConnection = model.getServerInfo().getAdmin();
        mDataModel = new ProfileImplDataModel();
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
        if (e.getSource().equals(mAdd)) {
            if (mEditor==null)
                mEditor = new ProfileRegisterDialog(mModel.getFrame(),
                  mConnection);
            mEditor.showDialog(mDestination, ScopeDef.SC_POLICY_IMPLS);
            refresh();
        }
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
            if(mTable.getSelectedRow()< 0)
                return;
            NameValuePairs obj = (NameValuePairs)
                    mDataModel.getObjectValueAt(mTable.getSelectedRow());    
            if (mViewer==null)
                mViewer = new ViewDialog(mModel.getFrame());
            mViewer.showDialog(obj.getValue(IMPL_NAME),
                               obj.getValue(IMPL_CLASS),
                               obj.getValue(IMPL_DESC));
        }        
        if (e.getSource().equals(mHelp)) {
            helpCallback();
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
        JButton[] buttons = {mAdd, mDelete, mView};
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
        mScrollPane.setHorizontalScrollBarPolicy(mScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
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
        NameValuePairs response = new NameValuePairs();
        NameValuePairs response1;
        NameValuePairs response2;
        NameValuePairs response3;
        NameValuePairs response4;
        NameValuePairs response5;
        try {
            response1 = mConnection.search(mDestination,
                               "profile",
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }
        for (Enumeration e = response1.getNames(); e.hasMoreElements() ;) {
            String entry = ((String)e.nextElement()).trim();
            response.add(entry+";profile", response1.getValue(entry));
        }
        try {
            response2 = mConnection.search(mDestination,
                               "profileInput",
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }
        for (Enumeration e = response2.getNames(); e.hasMoreElements() ;) {
            String entry = ((String)e.nextElement()).trim();
            response.add(entry+";profileInput", response2.getValue(entry));
        }
        try {
            response3 = mConnection.search(mDestination,
                               "profileOutput",
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }
        for (Enumeration e = response3.getNames(); e.hasMoreElements() ;) {
            String entry = ((String)e.nextElement()).trim();
            response.add(entry+";profileOutput", response3.getValue(entry));
        }
        try {
            response4 = mConnection.search(mDestination,
                               "defaultPolicy",
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }
        for (Enumeration e = response4.getNames(); e.hasMoreElements() ;) {
            String entry = ((String)e.nextElement()).trim();
            response.add(entry+";defaultPolicy", response4.getValue(entry));
        }
        try {
            response5 = mConnection.search(mDestination,
                               "constraintPolicy",
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }
        for (Enumeration e = response5.getNames(); e.hasMoreElements() ;) {
            String entry = ((String)e.nextElement()).trim();
            response.add(entry+";constraintPolicy", response5.getValue(entry));
        }

        //parse the data
        int i=0;
        String[] vals = new String[response.size()];
        Hashtable data = new Hashtable();
        for (Enumeration e = response.getNames(); e.hasMoreElements() ;) {
            String entry = ((String)e.nextElement()).trim();
            String value = response.getValue(entry);
            int x = value.indexOf(",");
            int x_end = value.lastIndexOf(",");
            int y = entry.indexOf(";");
            NameValuePairs obj = new NameValuePairs();
            obj.add(IMPL_NAME,entry.substring(0,y));
            obj.add(IMPL_TYPE,entry.substring(y+1));
            vals[i++]= entry ;
            obj.add(IMPL_CLASS, value.substring(0,x));
            obj.add(IMPL_DESC, value.substring(x+1,x_end));
            data.put(entry,obj);
        }
        
        CMSAdminUtil.bubbleSort(vals);
        
        for (int y=0; y< vals.length ; y++) {
            mDataModel.processData(data.get(vals[y]));
        }
        
        data.clear();
        
        if (mDataModel.getRowCount() >0)
            mTable.setRowSelectionInterval(0,0);
            
        mModel.progressStop();
    }

    private void delete() {
        //get entry name
        mModel.progressStart();
        NameValuePairs obj = (NameValuePairs)
            mDataModel.getObjectValueAt(mTable.getSelectedRow());

        //send comment to server for the removal of user
        try {
            mConnection.delete(mDestination,
                               obj.getValue(IMPL_TYPE),
                               obj.getValue(IMPL_NAME));
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
