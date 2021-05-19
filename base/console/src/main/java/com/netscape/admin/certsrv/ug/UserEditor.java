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
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

import javax.swing.BorderFactory;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.admin.certsrv.connection.BasicAuthenticator;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;

/**
 * User Information Editor - UI provides the user information
 * management functionality. The management of user certificate
 * is done by certificate management dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 *
 * @see com.netscape.admin.certsrv.ug.UserTab
 */
public class UserEditor extends JDialog
    implements ActionListener, MouseListener, DocumentListener
{
    private static final long serialVersionUID = 1L;

    /*==========================================================
     * variables
     *==========================================================*/
    private String PREFIX = "USEREDITOR";

    private JFrame mParentFrame;
    private AdminConnection mConnection;
    private String mUserName;
    private boolean mIsNewUser = false;
    private ResourceBundle mResource;
    protected DefaultListModel<String> mDataModel;

    protected JScrollPane mScrollPane;
    protected JList<String> mList;

    private boolean mUserAdded;
    private JButton mOK, mCancel, mHelp;
    private JLabel mPasswordLbl, mPasswordConfirmLbl;
    private JTextField mUserNameField, mFullNameField, mEMailField, mPhoneField, mStateField;
    private JPasswordField mPasswordField;
    private JPasswordField mPasswordConfirm;
    private JLabel mUserLabel, mMembership, mGroupLbl, dummy1;
    private JComboBox<String> mGroupBox;
    private static final String ADDHELPINDEX =
      "usersgroups-certsrv-add-user-dbox-help";
    private static final String EDITHELPINDEX =
      "usersgroups-certsrv-edit-user-dbox-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    public UserEditor( JFrame parent,
                        AdminConnection conn,  boolean isNew) {
        super(parent,true);
        mParentFrame = parent;
        mConnection = conn;
        mDataModel = new DefaultListModel<>();
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        setTitle(mResource.getString(PREFIX+"_TITLE"));
        mIsNewUser = isNew;
        if(!mIsNewUser)
            setSize(360, 370);
        else
            setSize(360, 350);
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
        setDisplay();

        if(!mIsNewUser) {
            mUserNameField.setVisible(false);
            mUserLabel.setVisible(true);
            mMembership.setVisible(true);
            mScrollPane.setVisible(true);
            mGroupLbl.setVisible(false);
            mGroupBox.setVisible(false);
            dummy1.setVisible(false);
        } else {
            mUserNameField.setVisible(true);
            mUserNameField.setText("");
            mUserLabel.setVisible(false);
            mUserLabel.setText("");
            mMembership.setVisible(false);
            mScrollPane.setVisible(false);
            mGroupLbl.setVisible(true);
            mGroupBox.setVisible(true);
            dummy1.setVisible(true);
        }
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    /**
     * show the windows
     * @param user user name
     * @param isNew true if this is a new entry
     */
    public void showDialog(String user) {

        //initialize and setup
        mUserName = user;
        mFullNameField.setText("");
        mEMailField.setText("");
        mPhoneField.setText("");
        mStateField.setText("");
        mPasswordField.setText("");
        mPasswordConfirm.setText("");

        mDataModel.clear();
        //mViewCert.setEnabled(false);

        if(!mIsNewUser) {
            mUserLabel.setText(user);
        } else {
            mUserNameField.setText("");
            mUserLabel.setText("");
            mStateField.setText("1");
        }

        //retrieve the cert record from the server
        try {
            if (mIsNewUser == false)
                refresh();
            else {
                addGroup();
            }
        } catch (EAdminException ex) {
            CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                    ex.toString(), CMSAdminUtil.ERROR_MESSAGE);
            return;
        }
        updateView();
        this.setVisible(true);
    }

    public boolean isUserAdded() {
        return mUserAdded;
    }

    /*==========================================================
     * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================

    @Override
    public void actionPerformed(ActionEvent evt) {

        mUserAdded = false;
        if (evt.getSource().equals(mOK)) {

            //check password field
            String pwd = mPasswordField.getText().trim();
            if (!pwd.equals("")) {
                if (!mPasswordConfirm.getText().trim().equals(pwd)) {
                    CMSAdminUtil.showMessageDialog(mParentFrame, mResource, PREFIX,
                        "PWDNOTMATCH", CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }
            }

            if (mIsNewUser) {

                //check text fields
                if (mUserNameField.getText().trim().equals("")) {
                    CMSAdminUtil.showMessageDialog(mParentFrame, mResource, PREFIX,
                        "NOUSERNAME", CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }

                try {
                    addUser();
                    mUserAdded = true;
                } catch (EAdminException e) {
                    //display error dialog
                    Debug.println(e.toString());
                    CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                        e.toString(), CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }

            } else {

                try {
                    modifyUser();
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
            if (mIsNewUser)
                CMSAdminUtil.help(ADDHELPINDEX);
            else
                CMSAdminUtil.help(EDITHELPINDEX);
        }

        /*
         * possible enhancement here to put in
         * a WIZARD that will take 1) B64E ,2)
         * ldap dir, 3) cert server for retrieval
         * we will do B64E first
         *
        if (evt.getSource().equals(mAddCert)) {
            //display dialog to add B64E
            if (mCertDialog==null)
                mCertDialog = new CertImportDialog(mParentFrame);
            mCertDialog.showDialog();
            if (!mCertDialog.isOK())
                return;

            //add entry
            Debug.println("Name="+mCertDialog.getCertName());
            Debug.println("B64E= "+mCertDialog.getB64E());
            NameValuePairs data = new NameValuePairs();
            data.add(CERT_NAME,mCertDialog.getCertName());
            data.add(CERT_DATA,mCertDialog.getB64E());
            data.add(CERT_VIEW,CERT_B64E);
            mDataModel.processData(data);
            refreshTable();
        }

        if (evt.getSource().equals(mViewCert)) {
            //display certificate pp
            NameValuePairs obj = (NameValuePairs)mDataModel.getObjectValueAt
                  (mTable.getSelectedRow());
            if (mViewDialog==null)
                mViewDialog = new CertViewDialog(mParentFrame);
            mViewDialog.showDialog(obj.getValue(CERT_NAME),obj.getValue(CERT_DATA));
        }

        if (evt.getSource().equals(mDeleteCert)) {
            if(mTable.getSelectedRow()< 0)
                return;
            int i = CMSAdminUtil.showConfirmDialog(mParentFrame, mResource,
                        PREFIX, "DELETE", CMSAdminUtil.WARNING_MESSAGE);
            if (i == JOptionPane.YES_OPTION) {
                deleteCert();
                Debug.println("Cert Deleted");
            }
        }
        */
    }

    //==== MOUSELISTENER ======================
    @Override
    public void mouseClicked(MouseEvent e) {
        //check if stuff is selected
        updateView();
    }

    @Override
    public void mousePressed(MouseEvent e) {}
    @Override
    public void mouseReleased(MouseEvent e) {
        updateView();
    }
    @Override
    public void mouseEntered(MouseEvent e) {}
    @Override
    public void mouseExited(MouseEvent e) {}


    //== DocumentListener ==
    @Override
    public void insertUpdate(DocumentEvent e) {
        updateView();
    }

    @Override
    public void removeUpdate(DocumentEvent e){
        updateView();
    }

    @Override
    public void changedUpdate(DocumentEvent e){
        updateView();
    }

    /*==========================================================
     * private methods
     *==========================================================*/

    /**
     * proactive verification
     */
    private void updateView() {
        if (mIsNewUser) {
            if (mUserNameField.getText().trim().equals("")) {
                mOK.setEnabled(false);
                return;
            }
        }
        if (mFullNameField.getText().trim().equals("")) {
            mOK.setEnabled(false);
            return;
        }
        /* ONLY UID is verify now
        if (mPasswordField.getText().trim().equals("")) {
            mOK.setEnabled(false);
            return;
        }
        */
        mOK.setEnabled(true);
    }

    /**
     * Construction of the initial UI components
     */
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
        gbc.fill = GridBagConstraints.BOTH;
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

    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, PREFIX, "OK", null, this);
        mCancel = CMSAdminUtil.makeJButton(mResource, PREFIX, "CANCEL", null, this);
        mHelp = CMSAdminUtil.makeJButton(mResource, PREFIX, "HELP", null, this);
        //JButton[] buttons = { mOK, mCancel, mHelp };
        JButton[] buttons = { mOK, mCancel };
        return CMSAdminUtil.makeJButtonPanel( buttons, true);
    }

    private JPanel makeContentPane() {

        new Insets(CMSAdminUtil.COMPONENT_SPACE,0,
                            CMSAdminUtil.COMPONENT_SPACE,0);

        //top panel
        JPanel top = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        CMSAdminUtil.resetGBC(gbc);
        top.setLayout(gb);

        JLabel label1 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "USERNAME", null);
        mUserNameField = new JTextField();
        mUserNameField.addMouseListener(this);
        mUserNameField.getDocument().addDocumentListener(this);
        mUserLabel = new JLabel();
        mUserLabel.setVisible(false);
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
                                 0,CMSAdminUtil.COMPONENT_SPACE);
        top.add( mUserLabel, gbc );
        top.add( mUserNameField, gbc );

        JLabel dummy = new JLabel();
        dummy.setVisible(false);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 0.0;
        top.add( dummy, gbc);

        JLabel label2 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "FULLNAME", null);
        mFullNameField = new JTextField();
        mFullNameField.addMouseListener(this);
        mFullNameField.getDocument().addDocumentListener(this);
        CMSAdminUtil.addEntryField(top, label2, mFullNameField, gbc);

        mPasswordLbl = CMSAdminUtil.makeJLabel(mResource, PREFIX, "PASSWORD", null);
        mPasswordField = new JPasswordField();
        mPasswordField.addMouseListener(this);
        mPasswordField.getDocument().addDocumentListener(this);
        mPasswordField.getBackground();
        CMSAdminUtil.addEntryField(top, mPasswordLbl, mPasswordField, gbc);

        mPasswordConfirmLbl = CMSAdminUtil.makeJLabel(mResource, PREFIX, "PASSWORDCONFIRM", null);
        mPasswordConfirm = new JPasswordField();
        mPasswordConfirm.addMouseListener(this);
        mPasswordConfirm.getDocument().addDocumentListener(this);
        CMSAdminUtil.addEntryField(top, mPasswordConfirmLbl, mPasswordConfirm, gbc);

        JLabel label4 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "EMAIL", null);
        mEMailField = new JTextField();
        CMSAdminUtil.addEntryField(top, label4, mEMailField, gbc);

        CMSAdminUtil.resetGBC(gbc);
        //gbc.gridheight = gbc.REMAINDER;
        JLabel label5 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "PHONE", null);
        mPhoneField = new JTextField();
        CMSAdminUtil.addEntryField(top, label5, mPhoneField, gbc);

        CMSAdminUtil.resetGBC(gbc);
        //gbc.gridheight = gbc.REMAINDER;
        JLabel label51 = CMSAdminUtil.makeJLabel(mResource, PREFIX, "STATE", null);
        mStateField = new JTextField();
        CMSAdminUtil.addEntryField(top, label51, mStateField, gbc);

        CMSAdminUtil.resetGBC(gbc);
        mGroupLbl = CMSAdminUtil.makeJLabel(mResource, PREFIX, "GROUP",null);
        mGroupBox = new JComboBox<>();
        //mGroupBox.addItem("Admin group");
        dummy1 = new JLabel(" ");
        CMSAdminUtil.addEntryField(top, mGroupLbl, mGroupBox, dummy1, gbc);

        mMembership = CMSAdminUtil.makeJLabel(mResource, PREFIX, "MEMBER", null);
        //group membership table
        mList = CMSAdminUtil.makeJList(mDataModel,6);
        mScrollPane = new JScrollPane(mList,
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
            JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION );
        mList.addMouseListener(this);
        mScrollPane.setBackground(Color.white);

        mScrollPane.setBorder(BorderFactory.createLoweredBevelBorder());
        //setLabelCellRenderer(mTable,0);

        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.gridx = 0;
        gbc.anchor = GridBagConstraints.NORTHEAST;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                CMSAdminUtil.COMPONENT_SPACE,0,0);
        top.add( mMembership, gbc );

        gbc.gridx++;
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 0.5;
        gbc.weighty=1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                CMSAdminUtil.COMPONENT_SPACE,0,CMSAdminUtil.COMPONENT_SPACE);
        top.add( mScrollPane, gbc );

        return top;
    }

    //=================================================
    // RETRIEVE INFO FROM SERVER SIDE
    //=================================================

    //retrieve group information from the server
    private void refresh() throws EAdminException {

        //construct NVP
        NameValuePairs config = new NameValuePairs();
        config.put(Constants.PR_USER_FULLNAME, "");
        config.put(Constants.PR_USER_EMAIL, "");
        config.put(Constants.PR_USER_PHONE, "");
        config.put(Constants.PR_USER_STATE, "");
        config.put(Constants.PR_USER_GROUP, "");

        NameValuePairs response;
        response = mConnection.read(DestDef.DEST_USER_ADMIN,
                                    ScopeDef.SC_USERS,
                                    mUserName,
                                    config);

        //setup the ui
        mUserNameField.setText(mUserName);
        mFullNameField.setText(response.get(Constants.PR_USER_FULLNAME));
        mEMailField.setText(response.get(Constants.PR_USER_EMAIL));
        mPhoneField.setText(response.get(Constants.PR_USER_PHONE));
        mStateField.setText(response.get(Constants.PR_USER_STATE));

        //parse group entry
        String userStr = response.get(Constants.PR_USER_GROUP);
        if ( (userStr != null) && (!userStr.trim().equals("")) ) {
            StringTokenizer tokenizer = new StringTokenizer(userStr, ",");
            while (tokenizer.hasMoreTokens()) {
                String groupstr = tokenizer.nextToken().trim();
                mDataModel.addElement(groupstr);
            }
        }

    }

    private void addGroup() throws EAdminException {
        NameValuePairs response = mConnection.search(DestDef.DEST_GROUP_ADMIN,
          ScopeDef.SC_GROUPS, new NameValuePairs());
        if (mGroupBox.getItemCount() > 0)
            mGroupBox.removeAllItems();
        for (String groupname : response.keySet()) {
            mGroupBox.addItem(groupname.trim());
        }

    }

    //add new group information
    private void addUser() throws EAdminException {

        //construct NVP
        NameValuePairs config = new NameValuePairs();
        config.put(Constants.PR_USER_FULLNAME, mFullNameField.getText().trim());
        config.put(Constants.PR_USER_PASSWORD, mPasswordField.getText().trim());
        config.put(Constants.PR_USER_EMAIL, mEMailField.getText().trim());
        config.put(Constants.PR_USER_PHONE, mPhoneField.getText().trim());
        config.put(Constants.PR_USER_STATE, mStateField.getText().trim());
        config.put(Constants.PR_USER_GROUP, (String) mGroupBox.getSelectedItem());
        config.put(Constants.PR_USER_TYPE, "");
        //config.add(Constants.PR_USER_CERT,"");
        //createCertEntry(config);

        //send request
        mConnection.add(DestDef.DEST_USER_ADMIN,
                           ScopeDef.SC_USERS,
                           mUserNameField.getText().trim(),
                           config);
    }

    //change new group information
    private void modifyUser() throws EAdminException {

        //construct NVP
        NameValuePairs config = new NameValuePairs();
        config.put(Constants.PR_USER_FULLNAME, mFullNameField.getText().trim());
        config.put(Constants.PR_USER_PASSWORD, mPasswordField.getText().trim());
        config.put(Constants.PR_USER_EMAIL, mEMailField.getText().trim());
        config.put(Constants.PR_USER_PHONE, mPhoneField.getText().trim());
        config.put(Constants.PR_USER_STATE, mStateField.getText().trim());
        config.put(Constants.PR_USER_TYPE, "");
        //createCertEntry(config);

        //send request
        mConnection.modify(DestDef.DEST_USER_ADMIN,
                           ScopeDef.SC_USERS,
                           mUserName,
                           config);

	// #343872
	// see if it is password change of the currently logged-in
	// user. If it is the case, we need to update Console password
	// cache
	String pwd = mPasswordField.getText().trim();
	if (!pwd.equals("")) {
		BasicAuthenticator auth = (BasicAuthenticator)
			mConnection.getAuthenticator();
		if (mUserName.equals(auth.getUserid()) &&
				!pwd.equals(auth.getPassword())) {
			auth.setPassword(pwd);
		}
	}
    }
}

