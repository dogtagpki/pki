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
 * Group Membership Editor
 *
 * @author Jack Pan-Chen
 * @version $Revision: 14593 $, $Date: 2007-05-01 16:35:45 -0700 (Tue, 01 May 2007) $
 * @see com.netscape.admin.certsrv.ug
 */
public class GroupEditor extends JDialog
    implements ActionListener, ListSelectionListener
{

    /*==========================================================
     * variables
     *==========================================================*/
    private String PREFIX = "GROUPEDITOR";

    private JFrame mParentFrame;
    private AdminConnection mConnection;
    private String mGroupName;
    private boolean mIsNewGroup = false;
    private ResourceBundle mResource;
    protected DefaultListModel mDataModel;
    protected UserListDialog mUserDialog = null;    //keeping a copy for reuse

    protected JScrollPane mScrollPane;
    protected JList mList;

    private JButton mOK, mCancel, mHelp, mAddUser, mDelete;
    private JTextField mGroupNameField, mGroupDescField;
    private JLabel mGroupNameLabel;
    
    private static final String ADDHELPINDEX = 
      "usersgroups-certsrv-add-group-dbox-help";
    private static final String EDITHELPINDEX = 
      "usersgroups-certsrv-edit-group-dbox-help";
    private String mHelpToken;

    /*==========================================================
     * constructors
     *==========================================================*/
    public GroupEditor(JFrame parent, AdminConnection conn) {
        super(parent,true);
        mParentFrame = parent;
		mConnection = conn;
        mDataModel = new DefaultListModel();
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());

        setSize(360, 300);
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
        setDisplay();
        //toFront();
    }

    /*==========================================================
	 * public methods
     *==========================================================*/

    /**
     * show the windows
     * @param users list of current groups
     */
    public void showDialog(String group, boolean isNew) {

        //initialize and setup
        mGroupName = group;
        mIsNewGroup = isNew;

        if (isNew)
            mHelpToken = ADDHELPINDEX;
        else
            mHelpToken = EDITHELPINDEX;

        mGroupDescField.setText("");
        mGroupNameField.setText("");

        mDataModel.clear();

		//disable name change
		if(!mIsNewGroup) {
		    mGroupNameField.setVisible(false);
		    mGroupNameLabel.setVisible(true);
		    mGroupNameLabel.setText(mGroupName);
		} else {
		    mGroupNameField.setVisible(true);
		    mGroupNameLabel.setVisible(false);
		}

        //retrieve the user record from the server
        try {
            if (mIsNewGroup == false)
                refresh();
        } catch (EAdminException ex) {
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                    ex.toString(), CMSAdminUtil.ERROR_MESSAGE);
            return;
        }

        setButtons();
        this.show();
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================

	public void actionPerformed(ActionEvent evt) {

        if (evt.getSource().equals(mOK)) {

            if (mIsNewGroup) {

                //check text fields
                if (mGroupNameField.getText().trim().equals("")) {
                    CMSAdminUtil.showMessageDialog(mParentFrame, mResource, PREFIX,
                        "NOGROUPNAME", CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }
                
                try {
                    mGroupName = mGroupNameField.getText().trim();
                    addGroup();
                } catch (EAdminException e) {
                    //display error dialog
                    Debug.println(e.toString());
                    CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                        e.toString(), CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }

            } else {

                try {
                    modifyGroup();
                } catch (EAdminException e) {
                    //display error dialog
                    Debug.println(e.toString());
                    CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                        e.toString(), CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }

            }
            this.hide();
        }

        if (evt.getSource().equals(mCancel)) {
            Debug.println("Cancel Pressed");

            //display are you sure dialog
            this.hide();
        }

        if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }

        if (evt.getSource().equals(mAddUser)) {
            //bring up the list for selection
           
            //create vector here
            Vector currentUser = new Vector();
            for (int i=0; i<mDataModel.getSize(); i++) {
                currentUser.addElement((String)mDataModel.getElementAt(i));
            }
            
            NameValuePairs response;
            try {
                response = mConnection.search(DestDef.DEST_USER_ADMIN,
                  ScopeDef.SC_USERS, new NameValuePairs());
                boolean hasNewUser = false;
                for (Enumeration e = response.getNames(); e.hasMoreElements() ;) {
                    String entry = ((String)e.nextElement()).trim();
                    if (currentUser.indexOf(entry)== -1)
                        hasNewUser = true;
                }
                if (!hasNewUser) {
                    CMSAdminUtil.showMessageDialog(mParentFrame, mResource, PREFIX,
                      "ALLUSERS", CMSAdminUtil.INFORMATION_MESSAGE);
                    return;
                }
            } catch (EAdminException e) {
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                  e.getMessage(), CMSAdminUtil.ERROR_MESSAGE);
                return;
            }

            if (mUserDialog==null)
                mUserDialog = new UserListDialog(mParentFrame, mConnection);
            
            mUserDialog.showDialog(currentUser);

            //get selection
            if (!mUserDialog.isOK())
                return;
                
            //create user NVP data object and add user entry
            Vector selectedUser = mUserDialog.getSelectedUser();
            //Debug.println("Selected User = "+selectedUser.toString());

            
            for(int i=0; i<selectedUser.size(); i++) {
                String name = ((String) selectedUser.elementAt(i)).trim();
                if (!isDuplicate(name))
                    mDataModel.addElement(name);
            }

            refreshTable();
        }

        if (evt.getSource().equals(mDelete)) {
            if(mList.getSelectedIndex()< 0)
                return;
            int i = CMSAdminUtil.showConfirmDialog(mParentFrame, mResource,
                        PREFIX, "DELETE", CMSAdminUtil.WARNING_MESSAGE);
            if (i == JOptionPane.YES_OPTION) {
                deleteMember();
                Debug.println("Member Deleted");
            }
            setButtons();
        }
	}

    private boolean isDuplicate(String name) {
        for (int i=0; i<mDataModel.getSize(); i++) {
            String name1 = ((String)mDataModel.getElementAt(i)).trim();
            if (name1.equals(name))
                return true;
        }
        return false;
    }

    public void valueChanged(ListSelectionEvent e) {
        setButtons();
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

    //resize vertical buttons
    private void resizeButtons() {
        mAddUser = CMSAdminUtil.makeJButton(mResource, PREFIX,"ADDUSER", null, this);
        //mAddGroup = CMSAdminUtil.makeJButton(mResource, PREFIX, "ADDGROUP", null, this);
        mDelete = CMSAdminUtil.makeJButton(mResource, PREFIX, "DELETE", null, this);
        JButton[] buttons = {mAddUser, mDelete};
        //JButton[] buttons = {mAddUser, mAddGroup, mDelete};
        JButtonFactory.resize( buttons );
    }

    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null, this);
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL", null, this);
        mHelp = CMSAdminUtil.makeJButton(mResource, PREFIX, "HELP", null, this);
		JButton[] buttons = { mOK, mCancel, mHelp };
        return CMSAdminUtil.makeJButtonPanel( buttons, true);
    }


    //create the vertical button panel for System Groups
    private JPanel createMemberButtonPanel() {
        //edit, add, delete, help buttons required
        //actionlister to this object
        JButton[] buttons = {mAddUser, mDelete};
		//JButton[] buttons = {mAddUser, mAddGroup, mDelete};
		return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

    private JPanel makeContentPane() {
        JPanel content = new JPanel();
        GridBagLayout gb3 = new GridBagLayout();
        content.setLayout(gb3);
        //content.setBorder(CMSAdminUtil.makeEtchedBorder());

        Insets insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,0,
                            CMSAdminUtil.COMPONENT_SPACE,0);

        //top panel
        JPanel top = new JPanel();
        GridBagLayout gb = new GridBagLayout();
		GridBagConstraints gbc = new GridBagConstraints();
		CMSAdminUtil.resetGBC(gbc);
        top.setLayout(gb);

        JLabel label1 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "GROUPNAME", null);
        mGroupNameField = new JTextField();
        mGroupNameLabel = new JLabel();
        mGroupNameLabel.setVisible(false);
        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.anchor = gbc.EAST;
        gbc. insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        top.add(label1, gbc);
        
        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc. insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,
                                 0,CMSAdminUtil.DIFFERENT_COMPONENT_SPACE);
        top.add( mGroupNameLabel, gbc );
        top.add( mGroupNameField, gbc );
        
        JLabel dummy = new JLabel();
        dummy.setVisible(false);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 0.0;
        top.add( dummy, gbc);

        CMSAdminUtil.resetGBC(gbc);
        //gbc.gridheight = gbc.REMAINDER;
        JLabel label2 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "GROUPDESC", null);
        mGroupDescField = new JTextField();
        CMSAdminUtil.addEntryField(top, label2, mGroupDescField, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label3 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "MEMBER", null);
        gbc.gridheight = gbc.REMAINDER;
        gbc.fill = gbc.NONE;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.anchor = gbc.WEST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                                CMSAdminUtil.COMPONENT_SPACE,0);
        top.add(label3, gbc );
        
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
        gb3.setConstraints(top, gbc);
        content.add(top);

        //bottom panel
        JPanel bottom = new JPanel();
        //bottom.setBorder(BorderFactory.createEtchedBorder());
        GridBagLayout gb2 = new GridBagLayout();
		CMSAdminUtil.resetGBC(gbc);
        bottom.setLayout(gb2);

        resizeButtons();

        //group membership table
        
        
        mList = makeJList(mDataModel,9);
        mList.addListSelectionListener(this);
        mScrollPane = new JScrollPane(mList,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        //mList.addMouseListener(this);
        mScrollPane.setBackground(Color.white);
        mScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.fill = gbc.BOTH;
        gbc.gridwidth = 1;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                            CMSAdminUtil.COMPONENT_SPACE,
                            CMSAdminUtil.COMPONENT_SPACE,
                            0);
        gb2.setConstraints(mScrollPane, gbc);
		bottom.add(mScrollPane);

		JPanel memberButtonPanel = createMemberButtonPanel();
		CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 0.0;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,0,
                            CMSAdminUtil.COMPONENT_SPACE,
                            CMSAdminUtil.DIFFERENT_COMPONENT_SPACE);
        gb2.setConstraints(memberButtonPanel, gbc);
		bottom.add(memberButtonPanel);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
        gb3.setConstraints(bottom, gbc);
        content.add(bottom);


        return content;
    }

	//Set the first column's cellrender as label cell
	protected void setLabelCellRenderer(JTable table, int index) {
	    table.getColumnModel().getColumn(index).setCellRenderer(new LabelCellRenderer(new JLabel()));
	}

    private void setButtons() {
        if (mList.getSelectedIndex() < 0) {
            mDelete.setEnabled(false);
        } else
            mDelete.setEnabled(true);
        CMSAdminUtil.repaintComp(mDelete);
    }

    //=================================================
    // RETRIEVE INFO FROM SERVER SIDE
    //=================================================

    //retrieve group information from the server
    private void refresh() throws EAdminException {
        //Call AdminConnection to get data mGroupName
        //mDataModel.removeAllRows();

        //construct NVP
        NameValuePairs config = new NameValuePairs();
        config.add(Constants.PR_GROUP_DESC, "");
        config.add(Constants.PR_GROUP_USER, "");
        config.add(Constants.PR_GROUP_GROUP, "");

        NameValuePairs response;
        response = mConnection.read(DestDef.DEST_GROUP_ADMIN,
                                    ScopeDef.SC_GROUPS,
                                    mGroupName,
                                    config);

        Debug.println("Received Memebership: "+response.toString());
        //setup the ui
        mGroupNameField.setText(mGroupName);
        mGroupDescField.setText(response.getValue(Constants.PR_GROUP_DESC));

        //setup the member table

        //parse user entry
        String user = response.getValue(Constants.PR_GROUP_USER).trim();
        StringTokenizer tokenizer = new StringTokenizer(user, ",");
        while (tokenizer.hasMoreTokens()) {
            String user_str = tokenizer.nextToken().trim();
            mDataModel.addElement(user_str);
        }
      
    }

    //add new group information
    private void addGroup() throws EAdminException {

            //construct NVP
            NameValuePairs config = new NameValuePairs();
            config.add(Constants.PR_GROUP_DESC, mGroupName);
            createUGString(config);

            //send request
            mConnection.add(DestDef.DEST_GROUP_ADMIN,
                               ScopeDef.SC_GROUPS,
                               mGroupName,
                               config);
    }

    //change new group information
    private void modifyGroup() throws EAdminException {

            //construct NVP
            NameValuePairs config = new NameValuePairs();
            config.add(Constants.PR_GROUP_DESC, mGroupDescField.getText());
            createUGString(config);

            //send request
            mConnection.modify(DestDef.DEST_GROUP_ADMIN,
                               ScopeDef.SC_GROUPS,
                               mGroupName,
                               config);

    }

    //remove member from the member list
    private void deleteMember() {
        Debug.println("GroupEditor: deleteMember()");
        int i = mList.getSelectedIndex();
        try{
            mDataModel.removeElementAt(i);
        } catch (Exception e) {
            Debug.println("GroupEditor: deleteMember()-" +e.toString());
        }
        refreshTable();
    }

    //create user and group membership string
    private void createUGString(NameValuePairs config) {
        StringBuffer userBuf = new StringBuffer();

        //go through membership table
        if(mDataModel.getSize()>0)
            for (int i=0; i<mDataModel.getSize(); i++) {
                String data = (String)mDataModel.getElementAt(i);
                if (userBuf.length()>0)
                    userBuf.append(",");
                userBuf.append(data);
            }

        //set parameters
        config.add(Constants.PR_GROUP_USER, userBuf.toString());
    }

    //refresh the table content
    private void refreshTable() {
        //Debug.println("GroupEditor: refreshTable() - start");
        //mTable.invalidate();
        //mTable.validate();
        //mTable.repaint(1);
		//mScrollPane.invalidate();
		//mScrollPane.validate();
		//mScrollPane.repaint(1);
		//Debug.println("GroupEditor: refreshTable() - end");
    }

    public JList makeJList(DefaultListModel listModel, int visibleCount) {
        JList listbox = new JList(listModel);
        listbox.setCellRenderer(new AttrCellRenderer());
        listbox.setSelectionModel(new DefaultListSelectionModel());
        listbox.setVisibleRowCount(visibleCount);
        if(listModel.size()!=0)
            listbox.setSelectedIndex(0);
        return listbox;
    }

}


