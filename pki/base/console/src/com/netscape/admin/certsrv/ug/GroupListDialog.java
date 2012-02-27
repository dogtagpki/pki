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
import javax.swing.event.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;
import javax.swing.table.*;
import com.netscape.management.client.*;
import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Group Listing Dialog - <p>
 *
 * This dialog support multiple group selection and displays
 * only groups that are not in the current group. This dialog
 * will be created once and being reused per group editor.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.ug
 */
public class GroupListDialog extends JDialog
    implements ActionListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    private String PREFIX = "GROUPLISTDIALOG";

    private JFrame mParentFrame;
    private AdminConnection mConnection;
    private ResourceBundle mResource;
    protected GroupListDataModel mDataModel;
    protected Vector mCurrentGroups;
    protected Vector mSelectedGroups;

    private JScrollPane mScrollPane;
    private JTable mTable;

    private JButton mOK, mCancel;
    private boolean mIsOk = false;

    /*==========================================================
     * constructors
     *==========================================================*/
    public GroupListDialog(JFrame parent, AdminConnection conn) {
        super(parent,true);
        mParentFrame = parent;
        mConnection = conn;
        mSelectedGroups = new Vector();
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        mDataModel = new GroupListDataModel();
        setSize(350, 300);
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
        setDisplay();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * show the windows
     * @param users list of current groups
     */
    public void showDialog(Vector groups) {

        mCurrentGroups = groups;
        mSelectedGroups.removeAllElements();

        //retrieve the cert record from the server
        try {
            refresh();
        } catch (EAdminException ex) {
            CMSAdminUtil.showMessageDialog(mParentFrame, mResource, PREFIX,
                    "SERVERERROR", CMSAdminUtil.ERROR_MESSAGE);
            return;
        }
        mIsOk = false;
        this.show();
    }


    /**
     * if selection is ok, the group names will be returned
     * otherwise, empty vector will be returned.
     * @return group names
     */
    public Vector getSelectedGroup() {
        return mSelectedGroups;
    }

    /**
     * get the exit code
     * @return true if ok; otherwise false
     */
    public boolean isOK() {
        return mIsOk;
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
	public void actionPerformed(ActionEvent evt) {
        if (evt.getSource().equals(mOK)) {
            //check if selection has been made
            //Debug.println("Row Selected = "+mDataModel.getRowCount());
            if(mDataModel.getRowCount()<=0) {
                //display error message
                CMSAdminUtil.showMessageDialog(mParentFrame, mResource, PREFIX,
                    "NOSELECTION", CMSAdminUtil.ERROR_MESSAGE);
                return;
            }

            //get selection
            //int i = mTable.getSelectedRowCount();
            //Debug.println("Rows Selected ="+i);
            int[] rowIndex = mTable.getSelectedRows();
            //Debug.println("Rows Selected ="+rowIndex.length);
            for (int j=0; j< rowIndex.length; j++)
                mSelectedGroups.addElement(
                    mDataModel.getObjectValueAt(rowIndex[j]));

            //set return flag
            mIsOk = true;
            this.hide();
        }

        if (evt.getSource().equals(mCancel)) {
            this.hide();
        }
    }

    /*==========================================================
	 * private methods
     *==========================================================*/
    private void setDisplay() {
        getContentPane().setLayout(new BorderLayout());
        JPanel center = new JPanel();
        GridBagLayout gb = new GridBagLayout();
		GridBagConstraints gbc = new GridBagConstraints();
        center.setLayout(gb);

        //content panel
        JPanel content = makeContentPane();
        CMSAdminUtil.resetGBC(gbc);
		gbc.anchor = gbc.NORTH;
		gbc.gridwidth = gbc.REMAINDER;
		gbc.weightx = 1.0;
		gbc.weighty = 1.0;
        gb.setConstraints(content, gbc);
		center.add(content);

		//action panel
		JPanel action = makeActionPane();
        CMSAdminUtil.resetGBC(gbc);
		gbc.anchor = gbc.NORTH;
		gbc.gridwidth = gbc.REMAINDER;
		gbc.gridheight = gbc.REMAINDER;
		gbc.weightx = 1.0;
        gb.setConstraints(action, gbc);
		center.add(action);

		getContentPane().add("Center",center);
    }

    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null, this);
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL", null, this);
		JButton[] buttons = { mOK, mCancel};
		JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel( buttons );
    }

    private JPanel makeContentPane() {
        JPanel content = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        content.setLayout(gb3);
        //content.setBorder(CMSAdminUtil.makeEtchedBorder());

        //left side certificate table
        mTable = new JTable(mDataModel);
		mScrollPane = JTable.createScrollPaneForTable(mTable);
		//mScrollPane.setBorder(CMSAdminUtil.makeTitledBorder(mResource,PREFIX,"CERTIFICATE"));
		mScrollPane.setHorizontalScrollBarPolicy(mScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		mScrollPane.setVerticalScrollBarPolicy(mScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		int width = CMSAdminUtil.getTotalColumnWidth( mTable );
		//Dimension d = new Dimension( width, mTable.getRowHeight()*14);
		//mTable.setMinimumSize( d );
		//mTable.setSize( d );
		mTable.setAutoscrolls(true);
		mTable.sizeColumnsToFit(true);
		mTable.getSelectionModel().setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		//mTable.getSelectionModel().addListSelectionListener(new StandardListSelectionListener());
		//mTable.addMouseListener(this);
		//mTable.setPreferredScrollableViewportSize(d);
		setLabelCellRenderer(mTable,0);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weighty = 1.0;
        gbc.weightx = 1.0;
        gb3.setConstraints(mScrollPane, gbc);
		content.add(mScrollPane);

        return content;
    }

	//Set the first column's cellrender as label cell
	protected void setLabelCellRenderer(JTable table, int index) {
	    table.getColumnModel().getColumn(index).setCellRenderer(new LabelCellRenderer(new JLabel()));
	}

    //=================================================
    // RETRIEVE INFO FROM SERVER SIDE
    //=================================================

    //retrieve group information from the server
    private void refresh() throws EAdminException {
        mDataModel.removeAllRows();

        NameValuePairs response;
        try {
            response = mConnection.search(DestDef.DEST_GROUP_ADMIN,
                               ScopeDef.SC_GROUPS,
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                    e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
            return;
        }

        //parse the data
        for (String entry : response.keySet()) {
            entry = entry.trim();
            //check if not already in current list
            if (mCurrentGroups.indexOf(entry)== -1)
                mDataModel.processData(entry);
        }

        refreshTable();
    }

    //refresh the table content
    private void refreshTable() {
        mTable.invalidate();
        mTable.validate();
        //mTable.repaint(1);
		mScrollPane.invalidate();
		mScrollPane.validate();
		//mScrollPane.repaint(1);
		repaint();
    }

}
