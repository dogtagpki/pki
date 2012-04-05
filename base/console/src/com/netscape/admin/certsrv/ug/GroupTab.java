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
package com.netscape.admin.certsrv.ug;

import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;

import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Group Tab
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 */
public class GroupTab extends CMSBaseUGTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANEL_NAME = "GROUPTAB";
    private AdminConnection mConnection;

    protected JScrollPane mScrollPane;
    protected JTable mTable;                 //table
    protected GroupDataModel mDataModel;     //table model
    protected GroupEditor mEditor=null;      //keep single copy

    protected JButton mRefresh, mEdit, mAdd, mDelete, mHelp;
    private static final String HELPINDEX = "usersgroups-certsrv-groups-help";

	/*==========================================================
     * constructors
     *==========================================================*/
    public GroupTab(CMSBaseResourceModel model) {
        super(PANEL_NAME, model);
        mConnection = model.getServerInfo().getAdmin();
        mDataModel = new GroupDataModel();
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
            Debug.println("Refresh Group");
            refresh();
        }
        if (e.getSource().equals(mEdit)) {
            if(mTable.getSelectedRow()< 0)
                return;

            Debug.println("Edit Groups "+mTable.getSelectedRow());
            String groupName = (String) mDataModel.getObjectValueAt(mTable.getSelectedRow());

            if (mEditor==null){
                mEditor = new GroupEditor(mModel.getFrame(), mConnection);
            }

            mEditor.showDialog(groupName, false);
            refresh();

        }
        if (e.getSource().equals(mAdd)) {
            Debug.println("Show Editor");
            if (mEditor==null)
                mEditor = new GroupEditor(mModel.getFrame(), mConnection);
            mEditor.showDialog("",true);
            refresh();
        }
        if (e.getSource().equals(mDelete)) {
            if(mTable.getSelectedRow()< 0)
                return;
            int i = showConfirmDialog("DELETE");
            if (i == JOptionPane.YES_OPTION) {
                deleteGroup();
                Debug.println("Group Deleted");
            }
        }
        if (e.getSource().equals(mHelp)) {
            helpCallback();
        }
    }

    //==== MOUSELISTENER ======================
    public void mouseClicked(MouseEvent e) {
        setButtons();

        /*

        //NEED TO DISABLE THIS DUE TO BUG THAT WILL RE-DISPLAY
        //THE DISLOG WINDOW AFTER CLOSING

        //NEED TO PUT CODE TO DO PROACTIVE VERIFICATION

        Debug.println("GroupTab: mouseClicked() -"+e.toString());

        //we track the double click action on the table entry - View op
        if(mTable.getSelectedRow() >= 0) {
            if(e.getClickCount() == 2) {
                Debug.println("Edit System group");
                String groupName = (String)
                mDataModel.getObjectValueAt(mTable.getSelectedRow());
                mEditor = new GroupEditor(mModel.getFrame(), mConnection);
                mEditor.showDialog(PrefixDef.PX_SYS+groupName,false);
                refresh();
            }
        }

        //we track the double click action on the table entry - View op
        if(mDefTable.getSelectedRow() >= 0) {
            if(e.getClickCount() == 2) {
                Debug.println("Edit Admin Define Group");
                String groupName = (String)
                mDefDataModel.getObjectValueAt(mDefTable.getSelectedRow());
                mEditor = new GroupEditor(mModel.getFrame(), mConnection);
                mEditor.showDialog(PrefixDef.PX_DEF+groupName,false);
                refresh();
            }
        }
        */

    }

    public void mouseReleased(MouseEvent e) {
        setButtons();
    }

    /*==========================================================
	 * protected methods
     *==========================================================*/

    /**
     * Updates the groups
     */
    public void refresh() {
        //Debug.println("refresh group");

        mDataModel.removeAllRows();

        updateGroup();
        setButtons();

        mTable.invalidate();
        mTable.validate();
        mTable.repaint(1);
		mScrollPane.invalidate();
		mScrollPane.validate();
		mScrollPane.repaint(1);
    }

    //resize vertical buttons
    protected void resizeButtons() {
        mEdit = makeJButton("EDIT");
        mAdd = makeJButton("ADD");
        mDelete = makeJButton("DELETE");
        //JButton[] buttons = {mEdit};
        JButton[] buttons = {mAdd, mDelete, mEdit};
        JButtonFactory.resize( buttons );
    }

    /**
     * create the bottom action button panel
     */
    protected JPanel createUDButtonPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
		// JButton[] buttons = { mEdit };
		JButton[] buttons = { mAdd, mDelete, mEdit };
		return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

    /**
     * create the bottom action button panel
     */
    protected JPanel createActionPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
	// JButton[] buttons = { mRefresh, mHelp };
	JButton[] buttons = { mRefresh };
		return makeJButtonPanel( buttons, true);
    }

    /**
     * create the center listing panel
     */
    protected JPanel createListPanel() {
		mListPanel = new JPanel();
		GridBagLayout gb = new GridBagLayout();
	    GridBagConstraints gbc = new GridBagConstraints();
		mListPanel.setLayout(gb);

		resizeButtons();

		//top standard table
		//fix the size of the top table - since the content will be fixed
		//also fixed the problem of resizing.
		mTable = new JTable(mDataModel);
		mScrollPane = JTable.createScrollPaneForTable(mTable);
		//mScrollPane.setBorder(CMSAdminUtil.makeTitledBorder(mResource,PANEL_NAME,"STANDARD"));
		mScrollPane.setHorizontalScrollBarPolicy(mScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		mScrollPane.setVerticalScrollBarPolicy(mScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		//int width = CMSAdminUtil.getTotalColumnWidth( mTable );
		//Dimension d = new Dimension( width, mTable.getRowHeight()*8);
		//mTable.setMinimumSize( d );
		//mTable.setSize( d );
		mTable.setAutoscrolls(true);
		mTable.sizeColumnsToFit(true);
		mTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		//mTable.getSelectionModel().addListSelectionListener(new StandardListSelectionListener());
		mTable.addMouseListener(this);
		//mTable.setPreferredScrollableViewportSize(d);
		mScrollPane.setBackground(Color.white);
		setLabelCellRenderer(mTable,0);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
      gbc.fill = gbc.BOTH;
        gbc.gridwidth = 1;
        gbc.weightx = 1.0;
        gbc.insets = EMPTY_INSETS;
        gb.setConstraints(mScrollPane, gbc);
        mListPanel.add(mScrollPane);

		JPanel buttonPanel = createUDButtonPanel();
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

	//=============================================
	// SEND REQUESTS TO THE SERVER SIDE
	//=============================================


   /**
     * set buttons - proactive verification
     */
    private void setButtons() {

        //enable and diable buttons accordingly
        if (mTable.getSelectionModel().isSelectionEmpty()) {
            mDelete.setEnabled(false);
            mEdit.setEnabled(false);
            return;
        }

        if(mDataModel.getRowCount()< 0) {
            mDelete.setEnabled(false);
            mEdit.setEnabled(false);
            return;
        }

        mDelete.setEnabled(true);
        mEdit.setEnabled(true);

    }

    private void updateGroup() {
        //send request and parse data

        NameValuePairs response;
        mModel.progressStart();
        try {
            response = mConnection.search(DestDef.DEST_GROUP_ADMIN,
                               ScopeDef.SC_GROUPS,
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }

        Debug.println(response.toString());

        //parse the data
        Vector store = new Vector();
        for (String entry : response.keySet()) {
            store.addElement(entry.trim());
        }

        String[] vals = new String[store.size()];
        store.copyInto(vals);

        CMSAdminUtil.bubbleSort(vals);

        for (int y=0; y< vals.length ; y++) {
            String value = response.get(vals[y]);
            mDataModel.processData(vals[y],value);
        }

        if (mDataModel.getRowCount() >0)
            mTable.setRowSelectionInterval(0,0);

        mModel.progressStop();
    }

    private void deleteGroup() {
        //get entry name
        String groupName = (String)
            mDataModel.getObjectValueAt(mTable.getSelectedRow());

        //send comment to server for the removal of the admin
        //defined group - no multiple groups selection - append
        //admin prefix
        mModel.progressStart();
        try {
            mConnection.delete(DestDef.DEST_GROUP_ADMIN,
                               ScopeDef.SC_GROUPS,
                               groupName);
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
