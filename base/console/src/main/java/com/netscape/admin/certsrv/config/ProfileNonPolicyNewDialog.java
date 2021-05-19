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

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.util.Vector;

import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.management.client.util.Debug;

/**
 * Policy Parameter Configuration Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class ProfileNonPolicyNewDialog extends CMSBaseConfigDialog
{
 protected JButton mRefresh, mEdit, mAdd, mDelete, mOrder, mHelp;
    protected JTextField mNameField=null, mDescField=null, mConfigField=null;
    protected JLabel mNameLabel=null, mDescLabel = null, mConfigLabel =null;
    protected JTable mTable = null;
    private String mParamId = null, mInputId = null;
    private String mScope = null;
    private boolean mIsNew = true;

    /*==========================================================
     * constructors
     *==========================================================*/
    public ProfileNonPolicyNewDialog(NameValuePairs nvp,
				JFrame parent,
				AdminConnection conn,
				String dest, String scope, boolean new1) {

        super(parent, dest);

		PREFIX = "PROFILEREGISTRYNEWDIALOG";
    	mHelpToken = "configuration-certificateprofiles";
		mImplName_token = Constants.PR_POLICY_IMPL_NAME;
		mImplType   = Constants.PR_EXT_PLUGIN_IMPLTYPE_POLICY;
        mIsNew = new1;
        mScope = scope;

		init(nvp,parent,conn,dest);
        setSize(500, 415);
    }


    protected JPanel makeContentPane() {
        JPanel mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);

    // 'Policy Rule ID' here
        CMSAdminUtil.resetGBC(gbc);
        mRulenameCaption = CMSAdminUtil.makeJLabel(mResource, PREFIX,
            "RULENAME", null);
        mRulenameCaption.addMouseListener(this);
        mPluginLabel = new JLabel();
        mPluginLabel.setVisible(false);
        mPluginName = new JTextField();

        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add(mRulenameCaption, gbc);

        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,
                                 0,CMSAdminUtil.COMPONENT_SPACE);
       mListPanel.add( mPluginName, gbc );
  //      mListPanel.add( mPluginLabel, gbc );

        // name
        CMSAdminUtil.resetGBC(gbc);
        mNameLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "NAMENAME", null);
        mNameLabel.addMouseListener(this);

        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        // mListPanel.add( mNameLabel, gbc );
	mNameLabel.setBackground(getBackground());
	mNameLabel.setEnabled(false);

        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        mNameField = new JTextField();
       // mListPanel.add( mNameField, gbc );

        // desc
        CMSAdminUtil.resetGBC(gbc);
        mDescLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "DESCNAME", null);
       // mDescLabel.addMouseListener(this);

        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add( mDescLabel, gbc );

        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        mDescField = new JTextField();
        mListPanel.add( mDescField, gbc );

        // config file
/*
        CMSAdminUtil.resetGBC(gbc);
        mConfigLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "CONFIGNAME", null);
        mConfigLabel.addMouseListener(this);

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
     //   mListPanel.add( mConfigLabel, gbc );

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        mConfigField = new JTextField();
       // mListPanel.add( mConfigField, gbc );
*/


    // 'Policy Plugin ID' here
        CMSAdminUtil.resetGBC(gbc);
        mImplnameCaption = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "IMPLNAME", null);
        mImplnameCaption.addMouseListener(this);

        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
 //       mListPanel.add( mImplnameCaption, gbc );

        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        mImplName = new JLabel();
//        mListPanel.add( mImplName, gbc );

       JPanel lpanel1 = createListPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = GridBagConstraints.BOTH;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(lpanel1, gbc);
        mListPanel.add(lpanel1);

    /* Panel in which to put plugin's help text */
        mHelpPanel = new JPanel();
        mHelpPanel.setBorder(CMSAdminUtil.makeEtchedBorder());
        mHelpLabel = new JTextArea(3,0);
        mHelpLabel.setLineWrap(true);
        mHelpLabel.setWrapStyleWord(true);
        mHelpLabel.setBackground(mHelpPanel.getBackground());
        mHelpLabel.setEditable(false);
        GridBagLayout gb2 = new GridBagLayout();
        GridBagConstraints gbc2 = new GridBagConstraints();

        CMSAdminUtil.resetGBC(gbc2);
        gbc2.fill = GridBagConstraints.BOTH;
        gbc2.anchor = GridBagConstraints.WEST;
        gbc2.gridwidth = GridBagConstraints.REMAINDER;
        gbc2.weightx = 1.0;
        gbc2.weighty = 1.0;
        gb2.setConstraints(mHelpLabel, gbc2);
        mHelpPanel.setLayout(gb2);
        mHelpPanel.add(mHelpLabel);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.SOUTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gb.setConstraints(mHelpPanel, gbc);
        mListPanel.add(mHelpPanel);

        return mListPanel;
    }

    public JPanel createListPanel()
    {
       Vector<String> colNames = new Vector<>();
       colNames.addElement("Parameter");
       colNames.addElement("Value");
       Vector<Vector<Object>> data = new Vector<>();
       Vector<Object> row = new Vector<>();
       row.addElement("x");
       row.addElement("x");
       data.addElement(row);

        JPanel mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);

        //center table
       ProfilePolicyEditDataModel model = new ProfilePolicyEditDataModel();
       model.setInfo(data, colNames);
        mTable = new JTable(model);
        JScrollPane mScrollPane = new JScrollPane(mTable);
        mScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        mScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setAutoscrolls(true);
        mTable.doLayout();
        mTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        // mTable.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        mTable.addMouseListener(this);
//        setLabelCellRenderer(mTable,0);
setLabelCellEditor(mTable, 1);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
      //  gbc.gridwidth = 1;
     //   gbc.weightx = 1.0;
        gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
        gb.setConstraints(mScrollPane, gbc);
        mListPanel.add(mScrollPane);

        return mListPanel;
    }

    public void actionPerformed(ActionEvent evt) {

        if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }

        if (evt.getSource().equals(mOK)) {

            try {
                if (mModel != null) {
                    mModel.progressStart();
                }

                NameValuePairs nvp = new NameValuePairs();
                String instanceName = mPluginName.getText();

                String id = mDescField.getText();
                if (id == null || id.trim().equals("")) {
                    String msg = mResource.getString(
                      PREFIX+"_DIALOG_BLANKPOLICYID_MESSAGE");
                    CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                       msg ,CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }

                for (int i = 0; i < mTable.getRowCount(); i++) {
                    nvp.put((String) mTable.getValueAt(i, 0),
                            (String) mTable.getValueAt(i, 1));
	            }

                if (mIsNew) {
                    String name = instanceName + ";" + id + ";" + mParamId;
                    // mAdminConnection.add(DestDef.DEST_CA_PROFILE_ADMIN,
                    mAdminConnection.add(mDest,
                      mScope, name, nvp);
                      //ScopeDef.SC_PROFILE_INPUT, name, nvp);
                } else {
                    String name = instanceName + ";" + id;
                    //mAdminConnection.modify(DestDef.DEST_CA_PROFILE_ADMIN,
                    mAdminConnection.modify(mDest,
                      mScope, name, nvp);
                      //ScopeDef.SC_PROFILE_INPUT_CONFIG, name, nvp);
                }

                mIsOK = true;
                if (mModel != null) {
                    mModel.progressStop();
                }

                this.dispose();
            }
            catch (EAdminException ex) {
                mModel.progressStop();
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                        ex.toString(),CMSAdminUtil.ERROR_MESSAGE);
            }
        }

        if (evt.getSource().equals(mCancel)) {
            this.dispose();
        }

    }

    public void showDialog(NameValuePairs data, String profileId, String paramId) {

        if (mIsNew)
            mParamId = paramId;
        else {
            mInputId = paramId;
            mDescField.setText(paramId);
            mDescField.setBackground(getBackground());
            mDescField.setEnabled(false);
        }

        mModel.progressStart();

        // retrieve profile information
        NameValuePairs response = null;
        NameValuePairs request = new NameValuePairs();
        try {
            if (mIsNew)
                response = mAdminConnection.read(DestDef.DEST_REGISTRY_ADMIN,
                             //ScopeDef.SC_PROFILE_INPUT,
                             mScope, paramId, request);
            else
                // response = mAdminConnection.read(DestDef.DEST_CA_PROFILE_ADMIN,
                response = mAdminConnection.read(mDest,
                    //ScopeDef.SC_PROFILE_INPUT_CONFIG,
                    mScope, profileId+";"+mInputId, request);
        } catch (EAdminException e) {
//          CMSAdminUtil.showErrorDialog(mParentFrame, mResource, e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();

        Vector<String> defcolNames = new Vector<>();
        defcolNames.addElement("Parameter");
        defcolNames.addElement("Value");
        Vector<Vector<Object>> defdata = new Vector<>();

        for (String entry : response.keySet()) {
           entry = entry.trim();
           String value = response.get(entry);
                  Debug.println("entry= " + entry);
                  Debug.println("value= " + value);

  int start_pos = value.indexOf(';');
  int end_pos = value.lastIndexOf(';');
  String syntax = null;
  String syntaxVal = null;
  String val = null;

   syntax = value.substring(0,start_pos);
   syntaxVal = value.substring(start_pos+1, end_pos);
   val = value.substring(end_pos+1);

           Vector<Object> row = new Vector<>();
           row.addElement(entry);
           row.addElement(val);
           defdata.addElement(row);
         }
         ProfilePolicyEditDataModel model = new ProfilePolicyEditDataModel();
         model.setInfo(defdata, defcolNames);
         mTable.setModel(model);

         if (response != null) {
             mPluginName.setText(profileId);
             mPluginName.setBackground(getBackground());
             mPluginName.setEnabled(false);
             mNameField.setText(response.get("name"));
             if (mIsNew)
                 mDescField.setText(response.get("desc"));
	    }

        this.setVisible(true);
    }

    protected void setLabelCellEditor(JTable table, int index) {
/*
        table.getColumnModel().getColumn(index).setCellRenderer(
          new PasswordCellRenderer());
*/
        table.getColumnModel().getColumn(index).setCellEditor(
          new DefaultCellEditor(new JTextField()));
    }
}
