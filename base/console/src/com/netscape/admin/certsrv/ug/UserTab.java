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
 * User Tab - this UI component provides the user
 * management functionality of the certificate server.
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 *
 * @see com.netscape.admin.certsrv.ug.CertImportDialog
 * @see com.netscape.admin.certsrv.ug.CertManagementDialog
 * @see com.netscape.admin.certsrv.ug.CertViewDialog
 * @see com.netscape.admin.certsrv.ug.UserEditor
 */
public class UserTab extends CMSBaseUGTab {

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANEL_NAME = "USERTAB";
    private AdminConnection mConnection;

    protected JScrollPane mScrollPane;
    protected JTable mTable;                    //table
    protected UserDataModel mDataModel;         //table model
    protected UserEditor mEditor=null;          //keep single copy
    protected UserEditor mAddEditor=null;       //keep single copy
    protected CertManagementDialog mCertEditor=null; //single copy
    protected JButton mRefresh, mEdit, mAdd, mDelete, mHelp, mCert;
    private final static String HELPINDEX = "usersgroups-certsrv-users-help";

	/*==========================================================
     * constructors
     *==========================================================*/
    public UserTab(CMSBaseResourceModel model) {
        super(PANEL_NAME, model);
        mConnection = model.getServerInfo().getAdmin();
        mDataModel = new UserDataModel();
        mHelpToken = HELPINDEX;
    }

    /*==========================================================
	 * public methods
     *==========================================================*/
     
    /**
     * refresh the content of the tab
     * IRefreshTab menthod
     */
    public void refresh() {
        //Debug.println("refresh() user tab");

        mDataModel.removeAllRows();
		updateUser();
        setButtons();
 		mTable.invalidate();
        mTable.validate();
		mScrollPane.invalidate();
		mScrollPane.validate();
		mScrollPane.repaint(1);
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent e) {
        if (e.getSource().equals(mRefresh)) {
            Debug.println("Refresh User");
            refresh();
        } else if (e.getSource().equals(mEdit)) {
            if(mTable.getSelectedRow()< 0)
                return;

            Debug.println("Edit User");
            String userName = (String)
                mDataModel.getObjectValueAt(mTable.getSelectedRow());

            mAddEditor = new UserEditor(mModel.getFrame(), mConnection,
              false);
            mAddEditor.showDialog(userName);
            mAddEditor.dispose();
            refresh();
        } else if (e.getSource().equals(mAdd)) {
            mAddEditor = new UserEditor(mModel.getFrame(), mConnection, true);
            mAddEditor.showDialog("");
            if (mAddEditor.isUserAdded())
                refresh();
            mAddEditor.dispose();
        } else if (e.getSource().equals(mDelete)) {
            Debug.println("Delete User");
            if(mTable.getSelectedRow()< 0)
                return;
            int i = showConfirmDialog("DELETE");
            if (i == JOptionPane.YES_OPTION) {
                deleteUser();
                Debug.println("User Deleted");
            }
        } else if (e.getSource().equals(mHelp)) {
            helpCallback();
        } else if (e.getSource().equals(mCert)) {
            String userName = (String)
                mDataModel.getObjectValueAt(mTable.getSelectedRow());
            if (mCertEditor==null)
                mCertEditor = new CertManagementDialog(mModel.getFrame(), mConnection);
            mCertEditor.showDialog(userName);
            Debug.println("Cert");
            //refresh();
            //XXX HELP
        }
    }

    //==== MOUSELISTENER ======================
    public void mouseClicked(MouseEvent e) {
        //Debug.println("CertRepositoryPanel: mouseClicked() -"+e.toString());
        setButtons();
        
        //we track the double click action on the table entry - View op
        if(mTable.getSelectedRow() >= 0) {
            if(e.getClickCount() == 2) {
                Debug.println("Edit User");
                //editUser();
            }
        }
    }
    
    public void mouseReleased(MouseEvent e) {
        setButtons();    
    }    

    /*==========================================================
	 * protected methods
     *==========================================================*/
     
    /**
     * create the user action button panel
     */
    protected JPanel createUserButtonPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mEdit = makeJButton("EDIT");
        mAdd = makeJButton("ADD");
        mDelete = makeJButton("DELETE");
        mCert = makeJButton("CERT");
		JButton[] buttons = {mAdd, mDelete, mEdit, mCert};
		JButtonFactory.resize( buttons );
		return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

    protected JPanel createActionPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        mRefresh = makeJButton("REFRESH");
        mHelp = makeJButton("HELP");
	//JButton[] buttons = { mRefresh, mHelp };
	JButton[] buttons = { mRefresh };
		return makeJButtonPanel( buttons, true);
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
		mTable.addMouseListener(this);
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

	    JPanel buttonPanel = createUserButtonPanel();
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

    /*==========================================================
	 * private methods
     *==========================================================*/

    /**
     * set buttons - proactive verification
     */
    private void setButtons() {

        //enable and diable buttons accordingly
        if (mTable.getSelectionModel().isSelectionEmpty()) {
            mDelete.setEnabled(false);
            mEdit.setEnabled(false);
            mCert.setEnabled(false);
            return;
        }

        if(mDataModel.getRowCount()< 0) {
            mDelete.setEnabled(false);
            mEdit.setEnabled(false);
            mCert.setEnabled(false);
            return;
        }

        mDelete.setEnabled(true);
        mEdit.setEnabled(true);
        mCert.setEnabled(true);

    }
    
	//=============================================
	// SEND REQUESTS TO THE SERVER SIDE
	//=============================================
	
	private void updateUser() {
        //send request and parse data

        NameValuePairs response;
        mModel.progressStart();

        try {
            response = mConnection.search(DestDef.DEST_USER_ADMIN,
                               ScopeDef.SC_USERS,
                               new NameValuePairs());
        } catch (EAdminException e) {
            //display error dialog
            showErrorDialog(e.getMessage());
            mModel.progressStop();
            return;
        }

        Debug.println(response.toString());

        String responseValue = response.get("userInfo");

        StringTokenizer tokenizer = new StringTokenizer(responseValue, ";");
        StringTokenizer subTokenizer = null;

        Vector store = new Vector();
        Hashtable table = new Hashtable();

        while (tokenizer.hasMoreTokens()) {
            String t = (String)tokenizer.nextToken();
            subTokenizer = new StringTokenizer(t, ":");
            int i=0;
            String str1 = null;
            String str2 = null;
            while (subTokenizer.hasMoreTokens()) {
                if (i == 0) {
                    str1 = (String)subTokenizer.nextToken();
                    store.addElement(str1);
                } else {
                    str2 = (String)subTokenizer.nextToken();
                    table.put(str1, str2);
                }
                i++;
            }
        }

        String[] names = new String[store.size()];
        store.copyInto(names);

        if (names.length > 1) {
            names = CMSAdminUtil.randomize(names);
            CMSAdminUtil.quickSort(names, 0, names.length-1);
        }

        for (int y=0; y< names.length ; y++) {
            String s = (String)table.get(names[y]);
            mDataModel.processData(names[y], s);
        }

        if (mDataModel.getRowCount() >0)
            mTable.setRowSelectionInterval(0,0);

        mModel.progressStop();
    }

    private void deleteUser() {
        //get entry name
        String userName = (String)
            mDataModel.getObjectValueAt(mTable.getSelectedRow());

        mModel.progressStart();
        //send comment to server for the removal of user
        try {
            mConnection.delete(DestDef.DEST_USER_ADMIN,
                               ScopeDef.SC_USERS,
                               userName);
        } catch (EAdminException e) {
            String str = e.toString();

            if (str.indexOf("The user") == 0) {
                int i = 
                  JOptionPane.showConfirmDialog(new JFrame(), str, 
                  "Information", JOptionPane.YES_NO_OPTION,
                  JOptionPane.INFORMATION_MESSAGE, 
                  CMSAdminUtil.getImage(CMSAdminResources.IMAGE_INFO_ICON));
                if (i == JOptionPane.YES_OPTION) {
                    Debug.println("User Deleted");
                    try {
                        mConnection.delete(DestDef.DEST_USER_ADMIN,
                               ScopeDef.SC_USERS,
                               userName+":true");
                    } catch (EAdminException ee) {
                        showErrorDialog(ee.getMessage());
                    }
                }
            }
        }

        mModel.progressStop();
        //send comment to server and refetch the content
        refresh();
    }

}
