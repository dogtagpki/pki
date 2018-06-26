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
import java.util.Vector;

import javax.swing.DefaultCellEditor;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.text.JTextComponent;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.PasswordCellRenderer;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.Constants;
import com.netscape.management.client.util.Debug;

/**
 * Old Agent name/password for reconfiguring the Recovery MN Scheme
 *
 * @author Jack Pan-Chen
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config
 */
class WMNOldAgent extends WizardBasePanel
    implements IWizardPanel
{

    /*==========================================================
     * variables
     *==========================================================*/
    private static final String PANELNAME = "WMNOLDAGENT";

    private int mNoAgent = 0;
    private MNSchemeWizardInfo mInfo;
    private AutoRecoveryModel mDataModel;
    private JTable mTable;
    protected JScrollPane mScrollPane;
    private static final String HELPINDEX =
      "configuration-kra-wizard-agentpwd-keyscheme-help";

    /*==========================================================
     * constructors
     *==========================================================*/
    WMNOldAgent() {
        super(PANELNAME);
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    /*==========================================================
     * public methods
     *==========================================================*/

    public boolean initializePanel(WizardInfo info) {
        //let's set the values
        mInfo = (MNSchemeWizardInfo)info;
        Debug.println(mInfo.toString());
        try {
            mNoAgent = Integer.parseInt(mInfo.getM());
        } catch (Exception e) {
            return false;
        }

        //add rows into tables
        //zap passwords
        mDataModel.removeAllRows();

        Vector<Object>[] data = new Vector[mNoAgent];
        for (int i=0; i<data.length; i++) {
            data[i] = new Vector<>();
            data[i].addElement(Integer.toString(i+1));
            data[i].addElement("");
            data[i].addElement("");
            mDataModel.addRow(data[i]);
        }

        return true;
    }

    public boolean validatePanel() {

        Component component = mTable.getEditorComponent();
        if(component!= null) {
            int col = mTable.getEditingColumn();
            int row = mTable.getEditingRow();
            if ((col>-1)&&(row>-1)) {
                String str = ((JTextComponent)component).getText();
                mTable.setValueAt(str, row, col);
            }
        }

        String val = getUIDPassword();
        if(val.equals("")) {
            setErrorMessage("CANNOTBEBLANK");
            return false;
        }
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        return true;
    }

    public void getUpdateInfo(WizardInfo info) {
            String val = getUIDPassword();
            mInfo.add(Constants.PR_OLD_RECOVERY_AGENT,val);
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    //base class take care of these
    //public String getTitle();
    //public String getErrorMessage();

    /*==========================================================
     * protected methods
     *==========================================================*/

    //Set the first column's cellrender as label cell
    protected void setLabelCellRenderer(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(
          new DefaultTableCellRenderer());
    }

    //Set the first column's cellrender as label cell
    protected void setLabelCellEditor(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(
          new PasswordCellRenderer());
        table.getColumnModel().getColumn(index).setCellEditor(
          new DefaultCellEditor(new JPasswordField()));
    }

    /*==========================================================
     * private methods
     *==========================================================*/

    //initialize the panel
    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JLabel label3 = makeJLabel("DESC");
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        add(label3,gbc);

        //table
        mDataModel = new AutoRecoveryModel();
        mTable = new JTable(mDataModel);
        mScrollPane = JTable.createScrollPaneForTable(mTable);
        //mScrollPane.setBorder(CMSAdminUtil.makeTitledBorder(mResource,PANEL_NAME,"USERS"));
        mScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        mScrollPane.setVerticalScrollBarPolicy(ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setAutoscrolls(true);
        mTable.sizeColumnsToFit(true);
        mTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        //mTable.getSelectionModel().addListSelectionListener(this);
        mScrollPane.setBackground(Color.white);
        setLabelCellRenderer(mTable, 1);
        setLabelCellEditor(mTable, 2);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        //gbc.gridheight = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,COMPONENT_SPACE,COMPONENT_SPACE);
        gb.setConstraints(mScrollPane, gbc);
        add(mScrollPane);

        super.init();
    }

    private String getUIDPassword() {
        String result = "";
        for (int i=0; i<mDataModel.getRowCount(); i++) {
            for (int j=1; j<mDataModel.getColumnCount(); j++) {
                String val = (String)mDataModel.getValueAt(i, j);
                if (val.equals(""))
                    return "";
                else if (j == (mDataModel.getColumnCount()-1))
                    result = result+val;
                else
                    result = result+val+"=";
            }
            if (i < (mDataModel.getRowCount()-1))
                result = result+",";
        }
        return result;
    }

}
