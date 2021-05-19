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

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.DefaultListSelectionModel;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import com.netscape.admin.certsrv.AttrCellRenderer;
import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.LabelCellRenderer;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.JButtonFactory;

/**
 * Group Membership Editor
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.ug
 */
public class GroupEditor extends JDialog
    implements ActionListener, ListSelectionListener
{
    private static final long serialVersionUID = 1L;

    /*==========================================================
     * variables
     *==========================================================*/
    private String PREFIX = "GROUPEDITOR";

    private JFrame mParentFrame;
    private AdminConnection mConnection;
    private String mGroupName;
    private boolean mIsNewGroup = false;
    private ResourceBundle mResource;
    protected DefaultListModel<String> mDataModel;
    protected UserListDialog mUserDialog = null;    //keeping a copy for reuse

    protected JScrollPane mScrollPane;
    protected JList<String> mList;

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
        mDataModel = new DefaultListModel<>();
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
        this.setVisible(true);
    }

    /*==========================================================
	 * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================

	@Override
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
            this.setVisible(false);
        }

        if (evt.getSource().equals(mCancel)) {
            Debug.println("Cancel Pressed");

            //display are you sure dialog
            this.setVisible(false);
        }

        if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }

        if (evt.getSource().equals(mAddUser)) {
            //bring up the list for selection

            //create vector here
            Vector<String> currentUser = new Vector<>();
            for (int i=0; i<mDataModel.getSize(); i++) {
                currentUser.addElement(mDataModel.getElementAt(i));
            }

            NameValuePairs response;
            try {
                response = mConnection.search(DestDef.DEST_USER_ADMIN,
                  ScopeDef.SC_USERS, new NameValuePairs());
                boolean hasNewUser = false;
                for (String entry : response.keySet()) {
                    entry = entry.trim();
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
            Vector<String> selectedUser = mUserDialog.getSelectedUser();
            //Debug.println("Selected User = "+selectedUser.toString());


            for(int i=0; i<selectedUser.size(); i++) {
                String name = selectedUser.elementAt(i).trim();
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
            String name1 = mDataModel.getElementAt(i).trim();
            if (name1.equals(name))
                return true;
        }
        return false;
    }

    @Override
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
		gbc.anchor = GridBagConstraints.NORTH;
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.weightx = 1.0;
		gbc.weighty = 1.0;
        gb.setConstraints(content, gbc);
		center.add(content);

		//action panel
		JPanel action = makeActionPane();
        CMSAdminUtil.resetGBC(gbc);
		gbc.anchor = GridBagConstraints.NORTH;
		gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.gridheight = GridBagConstraints.REMAINDER;
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
	//JButton[] buttons = { mOK, mCancel, mHelp };
	JButton[] buttons = { mOK, mCancel };
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

        new Insets(CMSAdminUtil.COMPONENT_SPACE,0,
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
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.anchor = GridBagConstraints.EAST;
        gbc. insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        top.add(label1, gbc);

        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc. insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,
                                 0,CMSAdminUtil.DIFFERENT_COMPONENT_SPACE);
        top.add( mGroupNameLabel, gbc );
        top.add( mGroupNameField, gbc );

        JLabel dummy = new JLabel();
        dummy.setVisible(false);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 0.0;
        top.add( dummy, gbc);

        CMSAdminUtil.resetGBC(gbc);
        //gbc.gridheight = gbc.REMAINDER;
        JLabel label2 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "GROUPDESC", null);
        mGroupDescField = new JTextField();
        CMSAdminUtil.addEntryField(top, label2, mGroupDescField, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label3 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "MEMBER", null);
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.fill = GridBagConstraints.NONE;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                CMSAdminUtil.DIFFERENT_COMPONENT_SPACE,
                                CMSAdminUtil.COMPONENT_SPACE,0);
        top.add(label3, gbc );

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
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
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
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
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 0.0;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,0,
                            CMSAdminUtil.COMPONENT_SPACE,
                            CMSAdminUtil.DIFFERENT_COMPONENT_SPACE);
        gb2.setConstraints(memberButtonPanel, gbc);
		bottom.add(memberButtonPanel);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
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
        config.put(Constants.PR_GROUP_DESC, "");
        config.put(Constants.PR_GROUP_USER, "");
        config.put(Constants.PR_GROUP_GROUP, "");

        NameValuePairs response;
        response = mConnection.read(DestDef.DEST_GROUP_ADMIN,
                                    ScopeDef.SC_GROUPS,
                                    mGroupName,
                                    config);

        Debug.println("Received Memebership: "+response.toString());
        //setup the ui
        mGroupNameField.setText(mGroupName);
        mGroupDescField.setText(response.get(Constants.PR_GROUP_DESC));

        //setup the member table

        //parse user entry
        String user = response.get(Constants.PR_GROUP_USER).trim();
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
            config.put(Constants.PR_GROUP_DESC, mGroupName);
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
            config.put(Constants.PR_GROUP_DESC, mGroupDescField.getText());
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
                String data = mDataModel.getElementAt(i);
                if (userBuf.length()>0)
                    userBuf.append(",");
                userBuf.append(data);
            }

        //set parameters
        config.put(Constants.PR_GROUP_USER, userBuf.toString());
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

    public JList<String> makeJList(DefaultListModel<String> listModel, int visibleCount) {
        JList<String> listbox = new JList<String>(listModel);
        listbox.setCellRenderer(new AttrCellRenderer<String>());
        listbox.setSelectionModel(new DefaultListSelectionModel());
        listbox.setVisibleRowCount(visibleCount);
        if(listModel.size()!=0)
            listbox.setSelectedIndex(0);
        return listbox;
    }

}


