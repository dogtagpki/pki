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
package com.netscape.admin.certsrv.config.install;

import java.util.*;
import java.awt.*;
import javax.swing.*;
import javax.swing.text.*;
import javax.swing.table.*;
import com.netscape.admin.certsrv.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.admin.certsrv.wizard.*;
import com.netscape.admin.certsrv.task.*;
import com.netscape.certsrv.common.*;
import com.netscape.management.client.console.*;

/**
 * KRA Key recovery for installation wizard: specify the uid and password
 * for all the available agents
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WIKRAScheme2Page extends WizardBasePanel implements IWizardPanel {
    private JTable mTable;
    private NewAgentModel mDataModel;
    private String mHelpIndex;
    private static final String PANELNAME = "KRASCHEME2WIZARD";
    private static final String KRAHELPINDEX =
      "install-kra-scheme-usrpwds-wizard-help";
    private static final String CAKRAHELPINDEX =
      "install-cakra-scheme-usrpwds-wizard-help";
    private static final String RAKRAHELPINDEX =
      "install-rakra-scheme-usrpwds-wizard-help";
    
    WIKRAScheme2Page(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WIKRAScheme2Page(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        if (!wizardInfo.doKeySplitting())
           return false;
        if (wizardInfo.isCloning())
            return false;
        if (!wizardInfo.isKRAInstalled() || wizardInfo.isKRANMSchemeDone())
            return false;

        String val = wizardInfo.getTotalAgents();
        int M = Integer.parseInt(val);
        mDataModel.removeAllRows();

        Vector[] data = new Vector[M];
        for (int i=0; i<data.length; i++) {
            data[i] = new Vector();
            data[i].addElement(Integer.toString(i+1));
		// initialize userid
            data[i].addElement("agent"+(i+1));
            data[i].addElement("");
            data[i].addElement("");
            mDataModel.addRow(data[i]);
        }

        setBorder(makeTitledBorder(PANELNAME));

        if (wizardInfo.isCAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = CAKRAHELPINDEX;
        else if (wizardInfo.isRAInstalled() && wizardInfo.isKRAInstalled())
            mHelpIndex = RAKRAHELPINDEX;
        else
            mHelpIndex = KRAHELPINDEX;

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

        if(!checkBlank()) {
            setErrorMessage("CANNOTBEBLANK");
            return false;
        }

        if(!checkConfirm()) {
            setErrorMessage("PASSWORDERROR");
            return false;
        }

        if (!checkDuplicate()) {
            setErrorMessage("DUPLICATEERROR");
            return false;
        }

        return true;
    }

    private boolean checkBlank() {
        for (int i=0; i<mDataModel.getRowCount(); i++) {
            String val1 = (String)mDataModel.getValueAt(i,1);
            String val2 = (String)mDataModel.getValueAt(i,2);
            String val3 = (String)mDataModel.getValueAt(i,3);
            if ( (val1.trim().equals(""))||(val2.trim().equals(""))||
                 (val3.trim().equals(""))) {
                return false;
            }
        }
        return true;
    }

    private boolean checkDuplicate() {
        Hashtable table = new Hashtable();
        for (int i=0; i<mDataModel.getRowCount(); i++) {
            String val1 = (String)mDataModel.getValueAt(i,1);
            table.put(val1.trim(), "1");
        }
        if (table.size() != mDataModel.getRowCount()) {
            table = null;
            return false;
        }

        table = null;
        return true;
    }

    private boolean checkConfirm() {
        for (int i=0; i<mDataModel.getRowCount(); i++) {
            String val2 = (String)mDataModel.getValueAt(i,2);
            String val3 = (String)mDataModel.getValueAt(i,3);
            if (!val2.trim().equals(val3.trim())) {
                return false;
            }
        }
        return true;
    }

    private String getUIDPassword() {
        String result = "";
        for (int i=0; i<mDataModel.getRowCount(); i++) {
            String val1 = (String)mDataModel.getValueAt(i,1);
            String val2 = (String)mDataModel.getValueAt(i,2);
            result = result+val1.trim()+"="+val2.trim();
            if (i < (mDataModel.getRowCount()-1))
                result = result+",";
        }
        return result;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
       
        String rawData = "";  
        int total = Integer.parseInt(wizardInfo.getTotalAgents());
        for (int i=0; i<total; i++) {
            String val1 = (String)mDataModel.getValueAt(i,1);
            String val2 = (String)mDataModel.getValueAt(i,2);
            rawData = rawData+ConfigConstants.PR_AGENT_UID+i+"="+val1;
            rawData = rawData+"&"+ConfigConstants.PR_AGENT_PWD+i+"="+val2;
        } 

        rawData = rawData+"&"+ConfigConstants.TASKID+"="+TaskId.TASK_AGENTS;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        rawData = rawData+"&"+ConfigConstants.PR_AGENT_N+"="+
          wizardInfo.getTotalAgents();
        rawData = rawData+"&"+ConfigConstants.PR_AGENT_M+"="+
          wizardInfo.getRequiredAgents();
        startProgressStatus();
        boolean ready = send(rawData, wizardInfo);
        endProgressStatus();

        if (!ready) {
            String str = getErrorMessage();
            if (str.equals("")) {
                String errorMsg = mResource.getString(
                  PANELNAME+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
                setErrorMessage(str);
        }

        return ready;
    }

    public void callHelp() {
        CMSAdminUtil.help(mHelpIndex);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea headingLbl = createTextArea(mResource.getString(
          PANELNAME+"_LABEL_HEADING_LABEL"));
        gbc.anchor = gbc.NORTHWEST;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE);
        gbc.gridwidth = gbc.REMAINDER;
        add(headingLbl, gbc);

        mDataModel = new NewAgentModel();
        mTable = new JTable(mDataModel);
        JScrollPane scrollPane = JTable.createScrollPaneForTable(mTable);
        scrollPane.setHorizontalScrollBarPolicy(scrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setVerticalScrollBarPolicy(scrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setAutoscrolls(true);
        mTable.sizeColumnsToFit(true);   
        mTable.getSelectionModel().setSelectionMode(ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        scrollPane.setBackground(Color.white);
        setLabelCellRenderer(mTable, 1);
        setLabelCellEditor(mTable, 2);
        setLabelCellEditor(mTable, 3);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTHWEST;
	gbc.fill = gbc.BOTH;
   gbc.weighty = 1.0;
   gbc.weightx = 1.0;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gb.setConstraints(scrollPane, gbc);
        add(scrollPane);

        super.init();
    }

    public void getUpdateInfo(WizardInfo info) {
    }

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
}

class NewAgentModel extends CMSTableModel
{
    /*==========================================================
     * variables
     *==========================================================*/
    public static final String COL1 = "NUMBER";
    public static final String COL2 = "UID";
    public static final String COL3 = "PASSWORD";
    public static final String COL4 = "CONFIRM";


    private static String[] mColumns = {COL1, COL2, COL3, COL4};

    /*==========================================================
     * constructors
     *==========================================================*/
    public NewAgentModel() {
        super();
        init(mColumns);
    }

    public boolean isCellEditable(int row, int col) {
        if(col >= 1)
            return true;
        return false;
    }
}
