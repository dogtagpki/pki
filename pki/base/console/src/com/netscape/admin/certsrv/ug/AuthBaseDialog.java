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
import javax.swing.text.*;
import java.awt.event.*;
import java.awt.*;
import java.util.*;

import com.netscape.management.client.util.*;
import com.netscape.certsrv.common.*;

/**
 * Auth Parameter Configuration Dialog
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.ug
 */
public class AuthBaseDialog extends JDialog
    implements ActionListener
{
    /*==========================================================
     * variables
     *==========================================================*/
    protected JFrame mParentFrame;
    protected ResourceBundle mResource;
    protected CMSTableModel mDataModel;
    protected NameValuePairs mData;
    protected JScrollPane mScrollPane;
    protected JTable mTable;
    protected String mRuleName;
    protected String mPrefix;
    protected String mType;
    protected JButton mOK, mCancel, mHelp;
    protected JTextField mAuthName;
    protected JLabel mImplName, mAuthLabel;
    protected AdminConnection mConn;

    /*==========================================================
     * constructors
     *==========================================================*/
    public AuthBaseDialog(JFrame parent, String type, String prefix) {
        super(parent, true);
        mParentFrame = parent;
        mPrefix = prefix;
        mType = type;
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        setSize(360, 316);
        setTitle(mResource.getString(mPrefix+"_TITLE"));
        setLocationRelativeTo(parent);
        getRootPane().setDoubleBuffered(true);
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    /**
     * show the windows
     * @param users list of current groups
     */
    // Changed by beomsuk
    /*public void showDialog(NameValuePairs data, String name, 
      boolean pinDirExist, boolean userDirExist) {*/
    public void showDialog(NameValuePairs data, String name, 
      boolean pinDirExist, boolean userDirExist, boolean portalExist) {
    // Change end
        mDataModel.removeAllRows();
        mData = data;

        mImplName.setText(data.get(Constants.PR_AUTH_IMPL_NAME));

        for (String entry : data.keySet()) {
            entry = entry.trim();
            if (!entry.equals(Constants.PR_AUTH_IMPL_NAME)) {
                String value = data.get(entry);
                Vector v = new Vector();
                v.addElement(entry);
                v.addElement(value);
                mDataModel.addRow(v);
            }
        }

        if ((name==null)||name.equals("")) {
            //new policy
            mAuthName.setVisible(true);
            mAuthName.setText("");
            mAuthLabel.setVisible(false);
            String str = mImplName.getText().trim();
            if (!pinDirExist && str.equals("UidPwdPinDirAuth"))
                mAuthName.setText("PinDirEnrollment");
            else if (!userDirExist && str.equals("UidPwdDirAuth"))
                mAuthName.setText("UserDirEnrollment");
            else if (!userDirExist && str.equals("UdnPwdDirAuth"))
                mAuthName.setText("UserDnEnrollment");
            else if (str.equals("NISAuth"))
                mAuthName.setText("NISAuth");
            // Inserted by beomsuk
            else if (!portalExist && str.equals("PortalEnroll"))
                mAuthName.setText("PortalEnrollment");
            // Insert end
        } else {
            //old one
            mRuleName = name;
            mAuthName.setVisible(false);
            mAuthLabel.setVisible(true);
            mAuthLabel.setText(name);
        }

        this.show();
    }

    protected NameValuePairs getData() {
        NameValuePairs response = new NameValuePairs();
        response.put(Constants.PR_AUTH_IMPL_NAME, mImplName.getText());
        for (int i=0; i< mDataModel.getRowCount(); i++) {
            response.put((String) mDataModel.getValueAt(i, 0),
                    (String) mDataModel.getValueAt(i, 1));
        }
        return response;
    }

    protected String getRuleName() {
        return mRuleName;
    }

    /*==========================================================
     * EVNET HANDLER METHODS
     *==========================================================*/

    //=== ACTIONLISTENER =====================
    public void actionPerformed(ActionEvent evt) {

        if (evt.getSource().equals(mOK)) {

            if(mAuthName.isVisible()) {
                mRuleName = mAuthName.getText();
                if (mRuleName.trim().equals("")) {
                    CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                        mResource.getString(mPrefix+"_DIALOG_NORULENAME_MESSAGE"),
                        CMSAdminUtil.ERROR_MESSAGE);
                    return;
                }
            }

            //save any current edit component
            Component component = mTable.getEditorComponent();
            if (component!= null) {
                int col = mTable.getEditingColumn();
                int row = mTable.getEditingRow();
                if ((col>-1)&&(row>-1)) {
                    String str = ((JTextComponent)component).getText();
                    mTable.setValueAt(str, row, col);
                }
            }
 
            try {
                if (mAuthName.isVisible())
                    addPolicyRule(getData(), getRuleName());
                else
                    modifyPolicyRule(getData(), getRuleName());
            } catch (EAdminException e) {
                CMSAdminUtil.showErrorDialog(mParentFrame, mResource,
                        e.toString(),CMSAdminUtil.ERROR_MESSAGE);
                return;
            }
        }

        if (evt.getSource().equals(mOK) || evt.getSource().equals(mCancel))
            this.dispose();
    }

    /*==========================================================
     * private methods
     *==========================================================*/
    protected void setDisplay() {
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

    //create botton action panel
    private JPanel makeActionPane() {
        mOK = CMSAdminUtil.makeJButton(mResource, mPrefix, "OK", null, this);
        if (mType.equals(Constants.VIEW))
            mOK.setEnabled(false);
        else
            mOK.setEnabled(true);
        mCancel = CMSAdminUtil.makeJButton(mResource, mPrefix, "CANCEL", null, this);
        mHelp = CMSAdminUtil.makeJButton(mResource, mPrefix, "HELP", null, this);
        // JButton[] buttons = { mOK, mCancel, mHelp};
        JButton[] buttons = { mOK, mCancel};
        JButtonFactory.resize( buttons );
        return CMSAdminUtil.makeJButtonPanel( buttons, true);
    }

    private JPanel makeContentPane() {
        JPanel mListPanel = new JPanel();
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        mListPanel.setLayout(gb);
        //content.setBorder(CMSAdminUtil.makeEtchedBorder());

        CMSAdminUtil.resetGBC(gbc);
        JLabel label1 = CMSAdminUtil.makeJLabel(mResource, mPrefix, "RULENAME", null);
        mAuthLabel = new JLabel();
        mAuthLabel.setVisible(false);
        mAuthName = new JTextField();

        gbc.fill = gbc.NONE;
        gbc.weightx = 0.0;
        gbc.anchor = gbc.EAST;
        gbc. insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,0,0);
        mListPanel.add(label1, gbc);

        gbc.anchor = gbc.WEST;
        gbc.fill = gbc.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc. insets = new Insets(CMSAdminUtil.COMPONENT_SPACE,
                                 CMSAdminUtil.COMPONENT_SPACE,
                                 0,CMSAdminUtil.COMPONENT_SPACE);
        mListPanel.add( mAuthLabel, gbc );
        mListPanel.add( mAuthName, gbc );

        JLabel dummy = new JLabel();
        dummy.setVisible(false);
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 0.0;
        mListPanel.add( dummy, gbc);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label3 = CMSAdminUtil.makeJLabel(mResource, mPrefix, "IMPLNAME", null);
        mImplName = new JLabel();
        CMSAdminUtil.addEntryField(mListPanel, label3, mImplName, gbc);

        //left side certificate table
        mTable = new JTable(mDataModel);
        mScrollPane = JTable.createScrollPaneForTable(mTable);
        //mScrollPane.setBorder(CMSAdminUtil.makeTitledBorder(mResource,PANEL_NAME,"USERS"));
        mScrollPane.setHorizontalScrollBarPolicy(mScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        mScrollPane.setVerticalScrollBarPolicy(mScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setAutoscrolls(true);
        mTable.sizeColumnsToFit(true);
        mTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        //mTable.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        setLabelCellRenderer(mTable,0);
        setLabelCellRenderer(mTable,1);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gb.setConstraints(mScrollPane, gbc);
        mListPanel.add(mScrollPane);

        return mListPanel;
    }

    //Set the first column's cellrender as label cell
    protected void setLabelCellRenderer(JTable table, int index) {
        //table.getColumnModel().getColumn(index).setCellRenderer(new DefaultTableCellRenderer());
        JLabel label = new JLabel();
        if (mType.equals(Constants.VIEW)) {
            label.setEnabled(false);
            table.getColumnModel().getColumn(index).setCellRenderer(
              new CustomLabelCellRenderer(label));
        } else {
            label.setEnabled(true);
            table.getColumnModel().getColumn(index).setCellRenderer(
              new LabelCellRenderer(label));
        }
    }

    public class CustomLabelCellRenderer extends LabelCellRenderer {
        public CustomLabelCellRenderer(JLabel x) {
            super(x);
        }

        public Component getTableCellRendererComponent(JTable table, 
          Object value, boolean isSelected, boolean hasFocus, int row, 
          int column) {

            if(value == null) {
                value = table.getModel().getValueAt(row, column);
            }
            this.value.setValue(value);
            component.setBackground(WHITECOLOR);
            component.setForeground(WHITECOLOR);
            return component;
        }
    }

    protected void addPolicyRule(NameValuePairs config, String name)
        throws EAdminException
    {
        mConn.add(DestDef.DEST_AUTH_ADMIN,
                        ScopeDef.SC_AUTH_MGR_INSTANCE,
                        name, config);
    }

    protected void modifyPolicyRule(NameValuePairs config, String name)
        throws EAdminException
    {
        mConn.modify(DestDef.DEST_AUTH_ADMIN,
                        ScopeDef.SC_AUTH_MGR_INSTANCE,
                        name, config);
    }
}
