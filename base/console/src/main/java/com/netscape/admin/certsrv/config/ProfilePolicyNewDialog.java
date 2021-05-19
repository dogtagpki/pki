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
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.FocusEvent;
import java.util.Hashtable;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.table.TableCellRenderer;

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
public class ProfilePolicyNewDialog extends CMSBaseConfigDialog
{
 protected JButton mRefresh, mEdit, mAdd, mDelete, mOrder, mHelp;
    protected JTextField mNameField=null, mIdField=null, mDescField=null, mConfigField=null;
    protected JLabel mNameLabel=null, mIdLabel=null, mDescLabel = null, mConfigLabel =null;
    protected JTable mDefaultTable = null, mConstraintTable = null;

    private String mConstraintId = null, mDefaultId = null;

     public String mDefSetId = null;
    protected Hashtable<Object, String> mHelpDesc = new Hashtable<>();

    /*==========================================================
     * constructors
     *==========================================================*/
    public ProfilePolicyNewDialog(String defSetId, NameValuePairs nvp,
				JFrame parent,
				AdminConnection conn,
				String dest) {

        super(parent, dest);

        mDefSetId = defSetId;
		PREFIX = "PROFILENEWDIALOG";
    	mHelpToken = "configuration-certificateprofiles";
		mImplName_token = Constants.PR_POLICY_IMPL_NAME;
		mImplType   = Constants.PR_EXT_PLUGIN_IMPLTYPE_POLICY;

		init(nvp,parent,conn,dest);
        setSize(500, 415);
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


        CMSAdminUtil.resetGBC(gbc);
        mIdLabel = CMSAdminUtil.makeJLabel(mResource, PREFIX,
         "IDNAME", null);

        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        gbc.gridwidth = 1;
        gbc.anchor = GridBagConstraints.EAST;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add( mIdLabel, gbc );

        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        mIdField = new JTextField();
        mListPanel.add( mIdField, gbc );

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

    /* Tab */
       JTabbedPane tabPane = new JTabbedPane();
       JPanel lpanel1 = createDefaultListPanel();
       JPanel lpanel2 = createConstraintListPanel();
        CMSAdminUtil.resetGBC(gbc);
        gbc.fill = GridBagConstraints.BOTH;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(tabPane, gbc);
        tabPane.addTab("Default", lpanel1);
        tabPane.addTab("Constraint", lpanel2);
        mListPanel.add(tabPane);

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

        return mListPanel;
    }

    public JPanel createDefaultListPanel()
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
        mDefaultTable = new ProfileDataTable(model);
        JScrollPane mScrollPane = new JScrollPane(mDefaultTable);
        mScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        mScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        mDefaultTable.setAutoscrolls(true);
        mDefaultTable.doLayout();
        mDefaultTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        // mTable.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        mDefaultTable.addMouseListener(this);
        mDefaultTable.setDefaultRenderer(JComponent.class, new JComponentCellRenderer());
        mDefaultTable.setDefaultEditor(JComponent.class, new ProfileComponentCellEditor());


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

/*
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
*/

        return mListPanel;
    }

    public JPanel createConstraintListPanel()
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
        mConstraintTable = new ProfileDataTable(model);
        JScrollPane mScrollPane = new JScrollPane(mConstraintTable);
        mScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        mScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        mConstraintTable.setAutoscrolls(true);
        mConstraintTable.doLayout();
        mConstraintTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        // mTable.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        mConstraintTable.addMouseListener(this);
        mConstraintTable.setDefaultRenderer(JComponent.class, new JComponentCellRenderer());
        mConstraintTable.setDefaultEditor(JComponent.class, new ProfileComponentCellEditor());

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

/*
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
*/

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

    @Override
    public void actionPerformed(ActionEvent evt) {

        if (evt.getSource().equals(mHelp)) {
            CMSAdminUtil.help(mHelpToken);
        }
        if (evt.getSource().equals(mAdd)) {
/*
  Debug.println("Add");
  PluginSelectionDialog dialog =
                      getPluginSelectionDialog(
                              mModel.getFrame(),
                              mConnection,
                              mDestination,
                              this
                              );

              dialog.setModel(mModel);
  dialog.showDialog();
  refresh();
*/
        }
        if (evt.getSource().equals(mDelete)) {
        }
        if (evt.getSource().equals(mEdit)) {
        }

        if (evt.getSource().equals(mOK)) {
            try {
                String policySetStr = mDescField.getText().trim();
                String policyIDStr = mIdField.getText().trim();
                if (policySetStr == null || policySetStr.length() == 0) {
                    String msg = mResource.getString(
                      PREFIX+"_DIALOG_BLANKPOLICYSET_MESSAGE");
                    CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                      msg ,CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }
                if (policyIDStr == null || policyIDStr.length() == 0) {
                    String msg = mResource.getString(
                      PREFIX+"_DIALOG_BLANKPOLICYID_MESSAGE");
                    CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                      msg ,CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }
                if (mModel != null) { mModel.progressStart(); }

                NameValuePairs nvp = new NameValuePairs();
                String instanceName = mPluginName.getText().trim();

		// create policy
                String policyId = policySetStr + ":" + policyIDStr;
		String name = instanceName + ";" + policyId + ";" + mDefaultId + ";" + mConstraintId;
                //mAdminConnection.add(DestDef.DEST_CA_PROFILE_ADMIN,
                mAdminConnection.add(mDest,
                  ScopeDef.SC_PROFILE_POLICIES, name, nvp);

/*
                nvp.add("impl", mImplName.getText());
                nvp.add("name", mNameField.getText());
                nvp.add("desc", mDescField.getText());
                nvp.add("config", mConfigField.getText());
*/

		for (int i = 0; i < mDefaultTable.getRowCount(); i++) {
            JComponent comp = (JComponent)mDefaultTable.getValueAt(i,1);
            String val = null;
            if (comp instanceof JTextField) {
                val = ((JTextField)comp).getText().trim();
            } else if (comp instanceof JComboBox) {
                val = (String)(((JComboBox<String>)comp).getSelectedItem());
            }
            String name1 = ((JLabel)(mDefaultTable.getValueAt(i,0))).getText();
            nvp.put(name1, val);
	        }


                //mAdminConnection.add(DestDef.DEST_CA_PROFILE_ADMIN,
                mAdminConnection.add(mDest,
                  ScopeDef.SC_PROFILE_DEFAULT_POLICY, name, nvp);

                mIsOK = true;
                if (mModel != null) { mModel.progressStop(); }

                nvp = new NameValuePairs();
		for (int i = 0; i < mConstraintTable.getRowCount(); i++) {
            JComponent comp = (JComponent)mConstraintTable.getValueAt(i,1);
            String val = null;
            if (comp instanceof JTextField) {
                val = ((JTextField)comp).getText().trim();
            } else if (comp instanceof JComboBox) {
                val = (String)(((JComboBox<String>)comp).getSelectedItem());
            }

            String name1 = ((JLabel)(mConstraintTable.getValueAt(i,0))).getText();
            nvp.put(name1, val);
	        }
                instanceName = mPluginName.getText();
                //mAdminConnection.add(DestDef.DEST_CA_PROFILE_ADMIN,
                mAdminConnection.add(mDest,
                  ScopeDef.SC_PROFILE_CONSTRAINT_POLICY, name, nvp);

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

    @Override
    public void showDialog(NameValuePairs data, String name) {

        mModel.progressStart();

	// name = profileId;defId;configid
	StringTokenizer st = new StringTokenizer(name, ";");
	String profileId = st.nextToken();
	String defId = st.nextToken();
	String conId = st.nextToken();

        mDefaultId = defId;
        mConstraintId = conId;

        // retrieve profile information
        NameValuePairs response = null;
        NameValuePairs request = new NameValuePairs();
        try {
		name = profileId + ";" + defId;
          response = mAdminConnection.read(DestDef.DEST_REGISTRY_ADMIN,
                             ScopeDef.SC_PROFILE_DEFAULT_POLICY,
                             defId, request);
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
                  Debug.println("entry= "+entry);
                  Debug.println("value= "+value);

           Object obj = getComponent(value);
           Vector<Object> row = new Vector<>();
           ((Component)obj).addFocusListener(this);
           mHelpDesc.put(obj, getHelpDescription(value));
           row.addElement(new JLabel(entry));
           row.addElement(obj);
           defdata.addElement(row);
         }
         ProfilePolicyEditDataModel defmodel = new ProfilePolicyEditDataModel();
         defmodel.setInfo(defdata, defcolNames);
         mDefaultTable.setModel(defmodel);

	if (response != null) {
        	mPluginName.setText(profileId);
	        mPluginName.setBackground(getBackground());
        	mPluginName.setEnabled(false);
		mNameField.setText(response.get("name"));
		mDescField.setText(response.get("desc"));
	}

        // retrieve policy information
        mModel.progressStart();
        try {
		name = profileId + ";" + conId;
          response = mAdminConnection.read(DestDef.DEST_REGISTRY_ADMIN,
                             ScopeDef.SC_PROFILE_CONSTRAINT_POLICY,
                             conId,
                             request);
        } catch (EAdminException e) {
//          CMSAdminUtil.showErrorDialog(mParentFrame, mResource, e.toString());
          mModel.progressStop();
        }
        mModel.progressStop();

        Vector<String> colNames = new Vector<>();
        colNames.addElement("Parameter");
        colNames.addElement("Value");
        Vector<Vector<Object>> d = new Vector<>();

        for (String entry : response.keySet()) {
           entry = entry.trim();
           String value = response.get(entry);
                  Debug.println("entry= "+entry);
                  Debug.println("value= "+value);

           Object obj = getComponent(value);
           Vector<Object> row = new Vector<>();
           ((Component)obj).addFocusListener(this);
           mHelpDesc.put(obj, getHelpDescription(value));
           row.addElement(new JLabel(entry));
           row.addElement(obj);
           d.addElement(row);
         }
         ProfilePolicyEditDataModel model = new ProfilePolicyEditDataModel();
         model.setInfo(d, colNames);
         mConstraintTable.setModel(model);

        String desc = mDescField.getText();
        if (desc == null || desc.equals("")) {
          if (mDefSetId != null) {
             mDescField.setText(mDefSetId);
          }
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

    class JComponentCellRenderer implements TableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable table,
          Object value, boolean isSelected, boolean hasFocus, int row,
          int column) {
            return (JComponent)value;
        }
    }

    private Component getComponent(String value) {
       int start_pos = value.indexOf(';');
       int end_pos = value.lastIndexOf(';');
       int end1_pos = value.lastIndexOf(';',end_pos-1);
       String syntax = null;
       String syntaxVal = null;
       String v = null;

        syntax = value.substring(0,start_pos);
        syntaxVal = value.substring(start_pos+1, end1_pos);
        v = value.substring(end_pos+1);
/*
        StringTokenizer st = new StringTokenizer(value, ";");
        String syntax = null;
        String syntaxVal = null;
        String v = null;
        while (st.hasMoreTokens()) {
            try {
                syntax = st.nextToken();
                syntaxVal = st.nextToken();
                v = st.nextToken();
            } catch (Exception e) {
            }
        }
*/
        if (syntax != null) {
            return CMSAdminUtil.createTableCell(syntax, syntaxVal, v);
        }

        return null;
    }

    private String getHelpDescription(String value) {
        int start_pos = value.indexOf(';');
        int end_pos = value.lastIndexOf(';');
        int end1_pos = value.lastIndexOf(';',end_pos-1);
        String syntax = null;
        String syntaxVal = null;
        String v = null;
        syntax = value.substring(0,start_pos);
        syntaxVal = value.substring(start_pos+1, end_pos);
        v = value.substring(end1_pos+1,end_pos);
        return v;
    }

        /**
         * From focuslistener interface. This lets us know when a component
         * has received focus, so we can update the help text.
         */
        @Override
        public void focusGained(FocusEvent f) {
           Debug.println("focusGained");
           Component comp = f.getComponent();
           String desc = mHelpDesc.get(comp);
           if (desc != null) {
                mHelpLabel.setText(desc);
           }
        }

        /** need to supply this method for focuslistener, but we
         * really don't care about it
         */
        @Override
        public void focusLost(FocusEvent f) {
          Debug.println("focusLost");
        }
}
