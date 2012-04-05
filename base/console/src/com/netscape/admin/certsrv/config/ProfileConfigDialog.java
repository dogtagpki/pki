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
import javax.swing.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;

import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Policy Parameter Configuration Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class ProfileConfigDialog extends CMSBaseConfigDialog
    implements ActionListener
{
 protected JButton mRefresh, mEdit, mAdd, mDelete, mOrder, mHelp;
    protected JTextField mAuthField=null,mNameField=null, mDescField=null, mConfigField=null;
    protected JComboBox mVisibleField = null;
    protected JLabel mVisibleLabel=null,mAuthLabel=null,mNameLabel=null, mDescLabel = null, mConfigLabel =null;

    /*==========================================================
     * constructors
     *==========================================================*/
    public ProfileConfigDialog(NameValuePairs nvp,
				JFrame parent,
				AdminConnection conn,
				String dest) {

        super(parent, dest);

		PREFIX = "PROFILECONFIGDIALOG";
    	mHelpToken = "configuration-certificateprofiles";
		mImplName_token = Constants.PR_POLICY_IMPL_NAME;
		mImplType   = Constants.PR_EXT_PLUGIN_IMPLTYPE_POLICY;
		init(nvp,parent,conn,dest);
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

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add(mRulenameCaption, gbc);

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,
                                 0,CMSAdminUtil.COMPONENT_SPACE);
        mListPanel.add( mPluginName, gbc );
        mListPanel.add( mPluginLabel, gbc );

        // name
        CMSAdminUtil.resetGBC(gbc);
        mNameLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "NAMENAME", null);
        mNameLabel.addMouseListener(this);

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add( mNameLabel, gbc );

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        mNameField = new JTextField();
        mListPanel.add( mNameField, gbc );

        // desc
        CMSAdminUtil.resetGBC(gbc);
        mDescLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "DESCNAME", null);
        mDescLabel.addMouseListener(this);

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add( mDescLabel, gbc );

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        mDescField = new JTextField();
        mListPanel.add( mDescField, gbc );

	// visible
        CMSAdminUtil.resetGBC(gbc);
        mVisibleLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "VISIBLENAME", null);
        mVisibleLabel.addMouseListener(this);

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add( mVisibleLabel, gbc );

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        String[] item = {"true", "false"};
        mVisibleField = new JComboBox(item);
        mListPanel.add( mVisibleField, gbc );

	// authentication
        CMSAdminUtil.resetGBC(gbc);
        mAuthLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "AUTHNAME", null);
        mAuthLabel.addMouseListener(this);

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add( mAuthLabel, gbc );

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        mAuthField = new JTextField();
        mListPanel.add( mAuthField, gbc );

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
        mListPanel.add( mConfigLabel, gbc );

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        mConfigField = new JTextField();
        mListPanel.add( mConfigField, gbc );
*/


    // 'Policy Plugin ID' here
        CMSAdminUtil.resetGBC(gbc);
        mImplnameCaption = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "IMPLNAME", null);
        mImplnameCaption.addMouseListener(this);

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = gbc.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add( mImplnameCaption, gbc );

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        mImplName = new JLabel();
        mListPanel.add( mImplName, gbc );

    /* Tab */
/*
       JTabbedPane tabPane = new JTabbedPane();
       JPanel lpanel = createListPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = gbc.BOTH;
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        tabPane.addTab("Policies", lpanel);
        gb.setConstraints(tabPane, gbc);
        mListPanel.add(tabPane);
*/

    /* Panel for list of plugin's parameters */
        mParamPanel = new JPanel();
/*
        mScrollPane = new JScrollPane(mParamPanel);
        mScrollPane.setBorder(CMSAdminUtil.makeEtchedBorder());
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = gbc.BOTH;
        gbc.anchor = gbc.WEST;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(mScrollPane, gbc);
        mListPanel.add(mScrollPane);
*/

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
        gbc2.fill = gbc.BOTH;
        gbc2.anchor = gbc.WEST;
        gbc2.gridwidth = gbc.REMAINDER;
        gbc2.weightx = 1.0;
        gbc2.weighty = 1.0;
        gb2.setConstraints(mHelpLabel, gbc2);
        mHelpPanel.setLayout(gb2);
        mHelpPanel.add(mHelpLabel);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.SOUTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gb.setConstraints(mHelpPanel, gbc);
        mListPanel.add(mHelpPanel);

        return mListPanel;
    }

    public JPanel createListPanel()
    {
    //    GridBagLayout gb = new GridBagLayout();
     //   GridBagConstraints gbc = new GridBagConstraints();

       Vector colNames = new Vector();
       colNames.addElement("Defaults");
       colNames.addElement("Constraints");
       Vector data = new Vector();
       Vector row = new Vector();
       row.addElement("NoDefault");
       row.addElement("NoConstraint");
       data.addElement(row);

        JPanel mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);

        //center table
       ProfileConfigDataModel model = new ProfileConfigDataModel();
       model.setInfo(data, colNames);
        JTable mTable = new JTable(model);
        JScrollPane mScrollPane = JTable.createScrollPaneForTable(mTable);
        mScrollPane.setHorizontalScrollBarPolicy(mScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mScrollPane.setVerticalScrollBarPolicy(mScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setAutoscrolls(true);
        mTable.sizeColumnsToFit(true);
        mTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        // mTable.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        mTable.addMouseListener(this);
//        setLabelCellRenderer(mTable,0);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.fill = gbc.BOTH;
        gbc.gridwidth = 1;
        gbc.weightx = 1.0;
        gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
        gb.setConstraints(mScrollPane, gbc);
        mListPanel.add(mScrollPane);

        JPanel buttonPanel = createUserButtonPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
        gb.setConstraints(buttonPanel, gbc);
        mListPanel.add(buttonPanel);

        return mListPanel;
    }

    protected JPanel createUserButtonPanel() {
        Debug.println("CMSPluginInstanceTab::createUserButtonPanel()");
        //edit, add, delete, help buttons required
        //actionlister to this object
        mEdit = CMSAdminUtil.makeJButton(mResource, PREFIX, "EDIT", null, this);
        mAdd = CMSAdminUtil.makeJButton(mResource, PREFIX, "ADD", null, this);
        mDelete = CMSAdminUtil.makeJButton(mResource, PREFIX, "DELETE", null, this);
        JButton[] buttons = {mAdd, mDelete, mEdit};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

    public void actionPerformed(ActionEvent evt) {

        if (evt.getSource().equals(mOK)) {

            NameValuePairs nvp = new NameValuePairs();
            try {
                if (mModel != null) { mModel.progressStart(); }

                String instanceName = mPluginName.getText();
                nvp.put("impl", mImplName.getText());
                nvp.put("name", mNameField.getText());
                nvp.put("visible", (String) (mVisibleField.getSelectedItem()));
                nvp.put("auth", mAuthField.getText());
                nvp.put("desc", mDescField.getText());
           //     nvp.add("config", mConfigField.getText());
               // mAdminConnection.add(DestDef.DEST_CA_PROFILE_ADMIN,
                mAdminConnection.add(mDest,
                  ScopeDef.SC_PROFILE_RULES, instanceName, nvp);

                mIsOK = true;
                if (mModel != null) { mModel.progressStop(); }
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
        if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }

    }
}
