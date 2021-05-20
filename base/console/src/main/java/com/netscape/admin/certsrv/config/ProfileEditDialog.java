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
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.JButtonFactory;

/**
 * Policy Parameter Configuration Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
public class ProfileEditDialog extends CMSBaseConfigDialog
    implements ChangeListener
{
    protected JButton mRefresh, mOrder, mHelp;
    protected JTextField mAuthField=null,mNameField=null, mDescField=null, mConfigField=null;
    protected JLabel mVisibleLabel=null,mAuthLabel=null,mNameLabel=null, mDescLabel = null, mConfigLabel =null;
    protected JComboBox<String> mVisibleField = null;
    protected JTable mPolicyTable=null, mInputTable=null, mOutputTable=null,
      mAuthTable=null;

    protected String mDefSetId = null;
	protected String mName = null;
    protected JTabbedPane mTabbedPane = null;
    protected JButton mPolicyEdit, mPolicyAdd, mPolicyDelete;
    protected JButton mInputEdit, mInputAdd, mInputDelete;
    protected JButton mOutputEdit, mOutputAdd, mOutputDelete;

    /*==========================================================
     * constructors
     *==========================================================*/
    public ProfileEditDialog(NameValuePairs nvp,
				JFrame parent,
				AdminConnection conn,
				String dest) {

        super(parent, dest);

		PREFIX = "PROFILEEDITDIALOG";
        mHelpToken = "configuration-certificateprofiles";
		mImplName_token = Constants.PR_POLICY_IMPL_NAME;
		mImplType   = Constants.PR_EXT_PLUGIN_IMPLTYPE_POLICY;

		init(nvp,parent,conn,dest);
        setSize(540, 440);
    }


    @Override
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
        mListPanel.add( mPluginLabel, gbc );

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
        mListPanel.add( mNameLabel, gbc );

        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        mNameField = new JTextField();
        mListPanel.add( mNameField, gbc );

        // desc
        CMSAdminUtil.resetGBC(gbc);
        mDescLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "DESCNAME", null);
        mDescLabel.addMouseListener(this);

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

	// visible
        CMSAdminUtil.resetGBC(gbc);
        mVisibleLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "VISIBLENAME", null);
        mVisibleLabel.addMouseListener(this);

        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add( mVisibleLabel, gbc );

        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        String[] item = {"true", "false"};
        mVisibleField = new JComboBox<>(item);
        mListPanel.add( mVisibleField, gbc );

	// auth
        CMSAdminUtil.resetGBC(gbc);
        mAuthLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "AUTHNAME", null);
        mAuthLabel.addMouseListener(this);

        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add( mAuthLabel, gbc );

        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
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
   //     mListPanel.add( mConfigLabel, gbc );

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = gbc.REMAINDER;
        mConfigField = new JTextField();
    //    mListPanel.add( mConfigField, gbc );

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
        mListPanel.add( mImplnameCaption, gbc );

        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        mImplName = new JLabel();
        mListPanel.add( mImplName, gbc );

        /* Tab */
        mTabbedPane = new JTabbedPane();
        Vector<String> policyColNames = new Vector<>();
        policyColNames.addElement("Set Id");
        policyColNames.addElement("Id");
        policyColNames.addElement("Defaults");
        policyColNames.addElement("Constraints");
        Vector<Vector<Object>> policyData = new Vector<>();
        Vector<Object> policyRow = new Vector<>();
        policyRow.addElement("p1");
        policyRow.addElement("p1");
        policyRow.addElement("NoDefault");
        policyRow.addElement("NoConstraint");
        policyData.addElement(policyRow);
        ProfileEditDataModel model = new ProfileEditDataModel();
        model.setInfo(policyData, policyColNames);
        mPolicyTable = new JTable(model);
        mPolicyEdit = CMSAdminUtil.makeJButton(mResource, PREFIX, "EDIT", null, this);
        mPolicyAdd = CMSAdminUtil.makeJButton(mResource, PREFIX, "ADD", null, this);
        mPolicyDelete = CMSAdminUtil.makeJButton(mResource, PREFIX, "DELETE", null, this);
        JPanel buttonPanel = createUserButtonPanel(mPolicyAdd,
          mPolicyDelete, mPolicyEdit);
        JPanel lpanel = createListPanel(mPolicyTable, buttonPanel,
          policyColNames, policyData);

        Vector<String> inputColNames = new Vector<>();
        inputColNames.addElement("Id");
        inputColNames.addElement("Inputs");
        Vector<Vector<Object>> inputData = new Vector<>();
        Vector<Object> inputRow = new Vector<>();
        inputRow.addElement("i1");
        inputRow.addElement("NoInput");
        inputData.addElement(inputRow);
        ProfileEditDataModel model1 = new ProfileEditDataModel();
        model1.setInfo(inputData, inputColNames);
        mInputTable = new JTable(model1);
        mInputEdit = CMSAdminUtil.makeJButton(mResource, PREFIX, "EDIT", null, this);
        mInputAdd = CMSAdminUtil.makeJButton(mResource, PREFIX, "ADD", null, this);
        mInputDelete = CMSAdminUtil.makeJButton(mResource, PREFIX, "DELETE", null, this);
        JPanel buttonPanel1 = createUserButtonPanel(mInputAdd,
          mInputDelete, mInputEdit);
        JPanel lpanel1 = createListPanel(mInputTable, buttonPanel1,
          inputColNames, inputData);

        Vector<String> outputColNames = new Vector<>();
        outputColNames.addElement("Id");
        outputColNames.addElement("Outputs");
        Vector<Vector<Object>> outputData = new Vector<>();
        Vector<Object> outputRow = new Vector<>();
        outputRow.addElement("i1");
        outputRow.addElement("NoOutput");
        outputData.addElement(outputRow);
        ProfileEditDataModel model2 = new ProfileEditDataModel();
        model2.setInfo(outputData, outputColNames);
        mOutputTable = new JTable(model2);
        mOutputEdit = CMSAdminUtil.makeJButton(mResource, PREFIX, "EDIT", null, this);
        mOutputAdd = CMSAdminUtil.makeJButton(mResource, PREFIX, "ADD", null, this);
        mOutputDelete = CMSAdminUtil.makeJButton(mResource, PREFIX, "DELETE",
          null , this);
        JPanel buttonPanel2 = createUserButtonPanel(mOutputAdd,
          mOutputDelete, mOutputEdit);
        JPanel lpanel2 = createListPanel(mOutputTable, buttonPanel2,
          outputColNames, outputData);

//        JPanel lpanel2 = createOutputPanel();
//        JPanel lpanel3 = createAuthPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = GridBagConstraints.BOTH;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        mTabbedPane.addTab(mResource.getString(PREFIX+"_POLICIES_TAB"), lpanel);
        mTabbedPane.addTab(mResource.getString(PREFIX+"_INPUTS_TAB"), lpanel1);
        mTabbedPane.addTab(mResource.getString(PREFIX+"_OUTPUTS_TAB"), lpanel2);

        //mTabbedPane.addTab(mResource.getString(PREFIX+"_OUTPUTS_TAB"), lpanel2);
        //mTabbedPane.addTab(mResource.getString(PREFIX+"_AUTHS_TAB"), lpanel3);
        gb.setConstraints(mTabbedPane, gbc);
        mListPanel.add(mTabbedPane);

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
        mTabbedPane.addChangeListener(this);

        return mListPanel;
    }

    private JTable getTable() {
        int i = mTabbedPane.getSelectedIndex();
        if (i == 0) {
            return mPolicyTable;
        } else if (i == 1) {
            return mInputTable;
        } else if (i == 2) {
            return mOutputTable;
        }
        return null;
    }

    public JPanel createListPanel(JTable table, JPanel buttonPanel,
      Vector<String> column, Vector<Vector<Object>> datav)
    {
        Vector<String> colNames = column;
        Vector<Vector<Object>> data = datav;

        JPanel listPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        listPanel.setLayout(gb);

        //center table
        JScrollPane mScrollPane = new JScrollPane(table);
        mScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        mScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        table.setAutoscrolls(true);
        table.doLayout();
        table.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        // table.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        table.addMouseListener(this);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridwidth = 1;
        gbc.weightx = 1.0;
        gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
        gb.setConstraints(mScrollPane, gbc);
        listPanel.add(mScrollPane);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weightx = 0.0;
        gbc.weighty = 1.0;
        gbc.insets = CMSAdminUtil.DEFAULT_EMPTY_INSETS;
        gb.setConstraints(buttonPanel, gbc);
        listPanel.add(buttonPanel);

        return listPanel;
    }

    protected JPanel createUserButtonPanel(JButton add, JButton delete,
      JButton edit) {
        Debug.println("CMSPluginInstanceTab::createUserButtonPanel()");
        //edit, add, delete, help buttons required
        //actionlister to this object
        JButton[] buttons = {add, delete, edit};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonVPanel( buttons );
    }

    public void refresh()
    {
        showDialog(null, mName);
    }

    @Override
    public void stateChanged(ChangeEvent evt) {
        setProfileOtherInfo(mName);
    }

    @Override
    public void actionPerformed(ActionEvent evt) {

        if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }

        if (evt.getSource().equals(mPolicyAdd)) {
            String profileId = mPluginName.getText();
            Debug.println("Add Policy");
            ProfilePolicySelectionDialog dialog =
              new ProfilePolicySelectionDialog(mDefSetId, profileId,
                "PROFILEPOLICYSELDIALOG",
                mModel.getFrame(),
                mAdminConnection,
               DestDef.DEST_REGISTRY_ADMIN, mDest);

            dialog.setModel(mModel);
            dialog.setDisplay();
            dialog.showDialog();
            refresh();
        }

        if (evt.getSource().equals(mInputAdd)) {
            String profileId = mPluginName.getText();
            Debug.println("Add Input");
            ProfileNonPolicySelDialog dialog =
              new ProfileNonPolicySelDialog(profileId,
              "PROFILEINPUTSELDIALOG", mModel.getFrame(),
              mAdminConnection, DestDef.DEST_REGISTRY_ADMIN, mDest,
              ScopeDef.SC_PROFILE_INPUT);
            dialog.setModel(mModel);
            dialog.setDisplay();
            dialog.showDialog();
            refresh();
        }

        if (evt.getSource().equals(mOutputAdd)) {
            String profileId = mPluginName.getText();
            Debug.println("Add Output");
            ProfileNonPolicySelDialog dialog =
              new ProfileNonPolicySelDialog(profileId,
              "PROFILEOUTPUTSELDIALOG", mModel.getFrame(),
              mAdminConnection, DestDef.DEST_REGISTRY_ADMIN, mDest,
              ScopeDef.SC_PROFILE_OUTPUT);
            dialog.setModel(mModel);
            dialog.setDisplay();
            dialog.showDialog();
            refresh();
        }

        if (evt.getSource().equals(mPolicyDelete)) {
            JTable table = getTable();
            if (table.getSelectedRowCount() <= 0) {
                String msg = mResource.getString(
                  PREFIX+"_DIALOG_NOPOLICY_MESSAGE");
                    CMSAdminUtil.showErrorDialog(mModel.getFrame(),
                      mResource, msg, CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
            int i = CMSAdminUtil.showConfirmDialog(mParentFrame,
              mResource, PREFIX, "DELETE", CMSAdminUtil.WARNING_MESSAGE);
            if (i == JOptionPane.YES_OPTION) {
		        String policyId = (String)
                  table.getValueAt(table.getSelectedRow(), 0) + ":" +
                  table.getValueAt(table.getSelectedRow(), 1);
                try {
                    deletePolicy(mPluginName.getText().trim(),policyId);

                    ProfileEditDataModel model =
                      (ProfileEditDataModel)table.getModel();
                    model.removeRow(table.getSelectedRow());
                    table.invalidate();
                    table.validate();
                    table.repaint(1);
                } catch (EAdminException e) {
                    CMSAdminUtil.showErrorDialog(mParentFrame,
                      mResource, e.toString(), CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }
                Debug.println("Deleted");
            }
        }

        if (evt.getSource().equals(mInputDelete)) {
            JTable table = getTable();
            if (table.getSelectedRowCount() <= 0) {
                String msg = mResource.getString(
                  PREFIX+"_DIALOG_NOPOLICY_MESSAGE");
                    CMSAdminUtil.showErrorDialog(mModel.getFrame(),
                      mResource, msg, CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
            int i = CMSAdminUtil.showConfirmDialog(mParentFrame,
              mResource, PREFIX, "DELETE", CMSAdminUtil.WARNING_MESSAGE);
            if (i == JOptionPane.YES_OPTION) {
                String inputId = (String)
                  table.getValueAt(table.getSelectedRow(), 0);
                try {
                    deleteInput(mPluginName.getText().trim(),inputId);

                    ProfileEditDataModel model =
                      (ProfileEditDataModel)table.getModel();
                    model.removeRow(table.getSelectedRow());
                    table.invalidate();
                    table.validate();
                    table.repaint(1);
                } catch (EAdminException e) {
                    CMSAdminUtil.showErrorDialog(mParentFrame,
                      mResource, e.toString(), CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }
                Debug.println("Deleted");
            }
        }

        if (evt.getSource().equals(mOutputDelete)) {
            JTable table = getTable();
            if (table.getSelectedRowCount() <= 0) {
                String msg = mResource.getString(
                  PREFIX+"_DIALOG_NOPOLICY_MESSAGE");
                    CMSAdminUtil.showErrorDialog(mModel.getFrame(),
                      mResource, msg, CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
            int i = CMSAdminUtil.showConfirmDialog(mParentFrame,
              mResource, PREFIX, "DELETE", CMSAdminUtil.WARNING_MESSAGE);
            if (i == JOptionPane.YES_OPTION) {
                String outputId = (String)
                  table.getValueAt(table.getSelectedRow(), 0);
                try {
                    deleteOutput(mPluginName.getText().trim(),outputId);

                    ProfileEditDataModel model =
                      (ProfileEditDataModel)table.getModel();
                    model.removeRow(table.getSelectedRow());
                    table.invalidate();
                    table.validate();
                    table.repaint(1);
                } catch (EAdminException e) {
                    CMSAdminUtil.showErrorDialog(mParentFrame,
                      mResource, e.toString(), CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }
                Debug.println("Deleted");
            }
        }

        if (evt.getSource().equals(mPolicyEdit)) {
            JTable table = getTable();
            // pick selected entry
            if (table.getSelectedRowCount() <= 0) {
                CMSAdminUtil.showErrorDialog(mModel.getFrame(),
                  mResource,
                  "You must select a policy first",
                  CMSAdminUtil.ERROR_MESSAGE);
			    return;
            }
            String policyId = (String)
              table.getValueAt(table.getSelectedRow(), 0) + ":" +
              table.getValueAt(table.getSelectedRow(), 1);

            Debug.println("Edit");
            NameValuePairs nvp = new NameValuePairs();
            ProfilePolicyEditDialog dialog =
              new ProfilePolicyEditDialog(nvp,
              mModel.getFrame(),
              mAdminConnection,
            //  DestDef.DEST_CA_PROFILE_ADMIN);
              mDest);
            dialog.setModel(mModel);

            String name = mPluginName.getText() + ";" + policyId;
	        Debug.println(" XXXX name=" + name);
            dialog.showDialog(null, name);
        }

        if (evt.getSource().equals(mInputEdit)) {
            JTable table = getTable();
            // pick selected entry
            if (table.getSelectedRowCount() <= 0) {
                CMSAdminUtil.showErrorDialog(mModel.getFrame(),
                  mResource,
                  "You must select an input first",
                  CMSAdminUtil.ERROR_MESSAGE);
                            return;
            }
            String inputId = (String)
              table.getValueAt(table.getSelectedRow(), 0);

            Debug.println("Edit input");
            NameValuePairs nvp = new NameValuePairs();
            ProfileNonPolicyNewDialog dialog =
              new ProfileNonPolicyNewDialog(nvp,
              mModel.getFrame(),
              mAdminConnection,
              //DestDef.DEST_CA_PROFILE_ADMIN,
              mDest,
              ScopeDef.SC_PROFILE_INPUT_CONFIG, false);
            dialog.setModel(mModel);

            String name = mPluginName.getText() + ";" + inputId;
                Debug.println(" XXXX name=" + name);
            dialog.showDialog(null, mPluginName.getText().trim(), inputId);
        }

        if (evt.getSource().equals(mOutputEdit)) {
            JTable table = getTable();
            // pick selected entry
            if (table.getSelectedRowCount() <= 0) {
                CMSAdminUtil.showErrorDialog(mModel.getFrame(),
                  mResource,
                  "You must select an output first",
                  CMSAdminUtil.ERROR_MESSAGE);
                            return;
            }
            String outputId = (String)
              table.getValueAt(table.getSelectedRow(), 0);

            Debug.println("Edit output");
            NameValuePairs nvp = new NameValuePairs();
            ProfileNonPolicyNewDialog dialog =
              new ProfileNonPolicyNewDialog(nvp,
              mModel.getFrame(),
              mAdminConnection,
             // DestDef.DEST_CA_PROFILE_ADMIN,
              mDest,
              ScopeDef.SC_PROFILE_OUTPUT_CONFIG, false);
            dialog.setModel(mModel);

            String name = mPluginName.getText() + ";" + outputId;
                Debug.println(" XXXX name=" + name);
            dialog.showDialog(null, mPluginName.getText().trim(), outputId);
        }

        if (evt.getSource().equals(mOK)) {

            NameValuePairs nvp = new NameValuePairs();
            try {
                if (mModel != null)
                    mModel.progressStart();

                String instanceName = mPluginName.getText();
                nvp.put("impl", mImplName.getText());
                nvp.put("name", mNameField.getText());
                nvp.put("desc", mDescField.getText());
                nvp.put("visible", (String) (mVisibleField.getSelectedItem()));
                nvp.put("auth", mAuthField.getText());
        //      nvp.add("config", mConfigField.getText());

/*
         //       mAdminConnection.add(DestDef.DEST_CA_PROFILE_ADMIN,
                  ScopeDef.SC_PROFILE_RULES, instanceName, nvp);
*/
                //DestDef.DEST_CA_PROFILE_ADMIN,
                mAdminConnection.modify(mDest,
                  ScopeDef.SC_PROFILE_RULES, instanceName, nvp);

                mIsOK = true;
                if (mModel != null)
                    mModel.progressStop();
                this.dispose();
            } catch (EAdminException ex) {
                mModel.progressStop();
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                        ex.toString(),CMSAdminUtil.ERROR_MESSAGE);
            }
        }

        if (evt.getSource().equals(mCancel)) {
            this.dispose();
        }

    }

    private void deletePolicy(String profileId, String policyId)
      throws EAdminException{
        NameValuePairs nvps = new NameValuePairs();
        nvps.put("POLICYID", policyId);
        //mAdminConnection.delete(DestDef.DEST_CA_PROFILE_ADMIN,
        mAdminConnection.delete(mDest,
          ScopeDef.SC_PROFILE_POLICIES, profileId, nvps);
    }

    private void deleteInput(String profileId, String inputId)
      throws EAdminException{
        NameValuePairs nvps = new NameValuePairs();
        nvps.put("INPUTID", inputId);
        //mAdminConnection.delete(DestDef.DEST_CA_PROFILE_ADMIN,
        mAdminConnection.delete(mDest,
          ScopeDef.SC_PROFILE_INPUT, profileId, nvps);
    }

    private void deleteOutput(String profileId, String outputId)
      throws EAdminException{
        NameValuePairs nvps = new NameValuePairs();
        nvps.put("OUTPUTID", outputId);
        //mAdminConnection.delete(DestDef.DEST_CA_PROFILE_ADMIN,
        mAdminConnection.delete(mDest,
          ScopeDef.SC_PROFILE_OUTPUT, profileId, nvps);
    }

    @Override
    public void showDialog(NameValuePairs data, String name) {

        mName = name;
        setProfileInfo(name);
        setProfileOtherInfo(name);

        this.setVisible(true);
    }

    private void setProfileInfo(String name) {
        mModel.progressStart();

        // retrieve profile information
        NameValuePairs response = null;
        NameValuePairs request = new NameValuePairs();
        try {
            //response = mAdminConnection.read(DestDef.DEST_CA_PROFILE_ADMIN,
            response = mAdminConnection.read(mDest,
                             ScopeDef.SC_PROFILE_RULES,
                             name, request);
        } catch (EAdminException e) {
//          CMSAdminUtil.showErrorDialog(mParentFrame, mResource, e.toString());
            mModel.progressStop();
        }
        mModel.progressStop();

            String enable = response.get("enable");

	    if (response != null) {
		mPluginName.setEnabled(false);
                mPluginName.setBackground(getBackground());
        	mPluginName.setText(name);
		mNameField.setText(response.get("name"));
		mDescField.setText(response.get("desc"));
		mAuthField.setText(response.get("auth"));
		mVisibleField.setSelectedItem(response.get("visible"));
		mImplName.setText(response.get("plugin"));
 //     		mConfigField.setText(response.getValue("config"));
	    }
            if (enable != null && enable.equals("true")) {
               // disable everything
        	mNameField.setEnabled(false);
      		mDescField.setEnabled(false);
      		mAuthField.setEnabled(false);
      		mVisibleField.setEnabled(false);
      		mImplName.setEnabled(false);

                mPolicyEdit.setEnabled(false);
                mPolicyAdd.setEnabled(false);
                mPolicyDelete.setEnabled(false);

                mInputEdit.setEnabled(false);
                mInputAdd.setEnabled(false);
                mInputDelete.setEnabled(false);

                mOutputEdit.setEnabled(false);
                mOutputAdd.setEnabled(false);
                mOutputDelete.setEnabled(false);
            }
    }

    private void setProfileOtherInfo(String name) {
        if (mModel != null)
            mModel.progressStart();
        JTable table = getTable();
        NameValuePairs request = new NameValuePairs();
        NameValuePairs response = null;
        if (table == mPolicyTable) {
            try {
                response = mAdminConnection.read(
                  mDest,
                  ScopeDef.SC_PROFILE_POLICIES, name, request);
            } catch (EAdminException e) {
              CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                  e.toString(), CMSAdminUtil.ERROR_MESSAGE);
                if (mModel != null)
                    mModel.progressStop();
                return;
            }

            if (mModel != null)
                mModel.progressStop();
            if (response != null) {
              populatePolicies(response, table);
            }
        } else if (table == mInputTable) {
            try {
                response = mAdminConnection.read(
                  mDest,
                  ScopeDef.SC_PROFILE_INPUT, name, request);
            } catch (EAdminException e) {
              CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                  e.toString(), CMSAdminUtil.ERROR_MESSAGE);
                if (mModel != null)
                    mModel.progressStop();
                return;
            }

            if (mModel != null)
                mModel.progressStop();
            if (response != null) {
              populateNonPolicy(response, table);
            }
        } else if (table == mOutputTable) {
            try {
                response = mAdminConnection.read(
                  mDest,
                  ScopeDef.SC_PROFILE_OUTPUT, name, request);
            } catch (EAdminException e) {
              CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                  e.toString(), CMSAdminUtil.ERROR_MESSAGE);
                if (mModel != null)
                    mModel.progressStop();
                return;
            }

            if (mModel != null)
                mModel.progressStop();
            if (response != null) {
              populateNonPolicy(response, table);
            }
        } else {
            // do nothing
        }
    }

    private void populatePolicies(NameValuePairs response, JTable table) {
        Vector<String> colNames = new Vector<>();
        colNames.addElement("Set Id");
        colNames.addElement("Id");
        colNames.addElement("Defaults");
        colNames.addElement("Constraints");
        Vector<Vector<Object>> d = new Vector<>();

        for (String entry : response.keySet()) {
            entry = entry.trim();
            String value = response.get(entry);
            Debug.println("populatePolicies entry= "+entry);
            Debug.println("populatePolicies value= "+value);

            StringTokenizer st = new StringTokenizer(value, ";");
            String def = st.nextToken();
            String con = st.nextToken();
            Vector<Object> row = new Vector<>();

            StringTokenizer st1 = new StringTokenizer(entry, ":");
            String setId = st1.nextToken();
            String id = st1.nextToken();

            if (mDefSetId == null) {
              mDefSetId = setId;
            }
            row.addElement(setId);
            row.addElement(id);
            row.addElement(def);
            row.addElement(con);
            d.addElement(row);
        }
        ProfileEditDataModel model = new ProfileEditDataModel();
        model.setInfo(d, colNames);
        table.setModel(model);
    }

    private void populateNonPolicy(NameValuePairs response, JTable table) {
        Vector<String> colNames = new Vector<>();
        colNames.addElement("Id");
        if (table == mInputTable)
            colNames.addElement("Inputs");
        else if (table == mOutputTable)
            colNames.addElement("Outputs");
        Vector<Vector<Object>> d = new Vector<>();

        for (String entry : response.keySet()) {
            entry = entry.trim();
            String value = response.get(entry);
            Debug.println("populateNonPolicy entry= " + entry);
            Debug.println("populateNonPolicy value= " + value);

            Vector<Object> row = new Vector<>();
            row.addElement(entry);
            row.addElement(value);
            d.addElement(row);
        }
        ProfileEditDataModel model = new ProfileEditDataModel();
        model.setInfo(d, colNames);
        table.setModel(model);
    }
}
