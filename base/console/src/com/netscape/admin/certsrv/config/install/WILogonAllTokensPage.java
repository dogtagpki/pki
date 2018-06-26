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

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.DefaultCellEditor;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.table.DefaultTableCellRenderer;

import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.PasswordCellRenderer;
import com.netscape.admin.certsrv.config.ProfileComponentCellEditor;
import com.netscape.admin.certsrv.config.ProfileDataTable;
import com.netscape.admin.certsrv.config.ProfilePolicyEditDataModel;
import com.netscape.admin.certsrv.wizard.IWizardPanel;
import com.netscape.admin.certsrv.wizard.WizardBasePanel;
import com.netscape.admin.certsrv.wizard.WizardInfo;
import com.netscape.certsrv.common.ConfigConstants;
import com.netscape.certsrv.common.OpDef;
import com.netscape.certsrv.common.TaskId;

/**
 * This panel asks for the information of the current internal database.
 *
 * @author Christine Ho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.config.install
 */
class WILogonAllTokensPage extends WizardBasePanel implements IWizardPanel {
    private ProfileDataTable mTable;
    private static final String EMPTYSTR = " ";
    private static final String PANELNAME = "LOGONALLTOKENSWIZARD";
    private static final String HELPINDEX = "install-internaldb-configuration-wizard-help";

    WILogonAllTokensPage(JDialog parent) {
        super(PANELNAME);
        mParent = parent;
        init();
    }

    WILogonAllTokensPage(JDialog parent, JFrame adminFrame) {
        super(PANELNAME);
        mParent = parent;
        mAdminFrame = adminFrame;
        init();
    }

    public boolean isLastPage() {
        return false;
    }

    public boolean initializePanel(WizardInfo info) {
        setBorder(makeTitledBorder(PANELNAME));
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;

        String tokenList = wizardInfo.getTokensList();
        String tokenLoggedIn = wizardInfo.getTokensLogin();
        String tokenInits = wizardInfo.getTokensInit();
        StringTokenizer tokenizer = new StringTokenizer(tokenList, ":");
        StringTokenizer tokenizerLoggedIn = new StringTokenizer(tokenLoggedIn, ":");
        StringTokenizer tokenizerInits = new StringTokenizer(tokenInits, ":");
        String loggedIn = "";
        String inits = "";

        boolean logon = false;
        Vector<String> defcolNames = new Vector<>();
        defcolNames.addElement("Token Name");
        defcolNames.addElement("Password");
        Vector<Vector<Object>> defdata = new Vector<>();

        while (tokenizer.hasMoreElements()) {
            String token = (String)tokenizer.nextElement();
            loggedIn = (String)tokenizerLoggedIn.nextElement();
            inits = (String)tokenizerInits.nextElement();

           // if (loggedIn.equals("false")) {
                // always logon to the token.
                if (inits.equals("true")) {
                    Vector<Object> v = new Vector<>();
                    v.addElement(new JLabel(token));
                    v.addElement(new JPasswordField());
                    defdata.addElement(v);
                    logon = true;
                }
            //}
        }

        ProfilePolicyEditDataModel defmodel = new ProfilePolicyEditDataModel();
        defmodel.setInfo(defdata, defcolNames);
        mTable.setModel(defmodel);

        return logon;
    }

    public boolean validatePanel() {
        for (int i=0; i<mTable.getRowCount(); i++) {
            JComponent comp = (JComponent)mTable.getValueAt(i,1);
            if (comp instanceof JPasswordField) {
                String val2 = ((JPasswordField)comp).getText().trim();
                if (val2.trim().equals("")) {
                    setErrorMessage("CANNOTBEBLANK");
                    return false;
                }
            }
        }
        return true;
    }

    public boolean concludePanel(WizardInfo info) {
        InstallWizardInfo wizardInfo = (InstallWizardInfo)info;
        cleanUpWizardInfo(wizardInfo);
        String tokenNames = "";
        String pwds = "";

        String val1 = "";
        String val2 = "";
        for (int i=0; i<mTable.getRowCount(); i++) {
            JComponent comp = (JComponent)mTable.getValueAt(i,0);
            if (comp instanceof JLabel) {
                val1 = ((JLabel)comp).getText().trim();
            }
            JComponent comp1 = (JComponent)mTable.getValueAt(i,1);
            if (comp1 instanceof JPasswordField) {
                val2 = ((JPasswordField)comp1).getText().trim();
            }
            wizardInfo.put("TOKEN:"+val1, val2);
            if (i == 0) {
                tokenNames = val1;
                pwds = val2;
            } else {
                tokenNames = tokenNames+":"+val1;
                pwds = pwds+":"+val2;
            }
        }

        startProgressStatus();
        String rawData = ConfigConstants.PR_TOKEN_LOGONLIST+"="+tokenNames;
        rawData = rawData+"&"+ConfigConstants.PR_TOKEN_LOGON_PWDS+"="+pwds;
        rawData = rawData+"&"+ConfigConstants.TASKID+"="+TaskId.TASK_LOGON_ALL_TOKENS;
        rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_MODIFY;
        rawData = rawData+"&"+ConfigConstants.PR_CMS_SEED+"="+
          (new Long(WizardBasePanel.mSeed).toString());

        boolean ready = send(rawData, wizardInfo);

        if (!ready) {
            String str = getErrorMessage(wizardInfo);
            if (str == null) {
                String errorMsg = mResource.getString(
                  PANELNAME+"_ERRORMSG");
                setErrorMessage(errorMsg);
            } else
                setErrorMessage(str);
        } else {
            rawData = ConfigConstants.TASKID+"="+TaskId.TASK_TOKEN_INFO;
            rawData = rawData+"&"+ConfigConstants.OPTYPE+"="+OpDef.OP_READ;
            ready = send(rawData, wizardInfo);
        }

        if (!ready) {
            String str = getErrorMessage(wizardInfo);
            if (str == null)
                setErrorMessage("Server Error");
            else
                setErrorMessage(str);
        }

        endProgressStatus();

        return ready;
    }

    public void callHelp() {
        CMSAdminUtil.help(HELPINDEX);
    }

    protected void init() {
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        JTextArea desc = createTextArea(mResource.getString(
          PANELNAME+"_TEXT_HEADING_LABEL"));
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.weightx = 1.0;
        gbc.weighty = 0.0;
        gbc.insets = new Insets(COMPONENT_SPACE,COMPONENT_SPACE,
          COMPONENT_SPACE,COMPONENT_SPACE);
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        add(desc, gbc);

        Vector<String> colNames = new Vector<>();
        colNames.addElement("Token Name");
        colNames.addElement("Password");
        Vector<Vector<Object>> data = new Vector<>();
        Vector<Object> row = new Vector<>();
        row.addElement("x");
        row.addElement("x");
        data.addElement(row);
        ProfilePolicyEditDataModel dataModel = new ProfilePolicyEditDataModel();
        dataModel.setInfo(data, colNames);
        mTable = new ProfileDataTable(dataModel);
        JScrollPane scrollPane = JTable.createScrollPaneForTable(mTable);
        scrollPane.setHorizontalScrollBarPolicy(
          ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setVerticalScrollBarPolicy(
          ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setAutoscrolls(true);
        mTable.sizeColumnsToFit(true);
        mTable.getSelectionModel().setSelectionMode(
          ListSelectionModel.SINGLE_INTERVAL_SELECTION);
        scrollPane.setBackground(Color.white);
        mTable.setDefaultRenderer(JComponent.class, new ComponentCellRenderer());
        mTable.setDefaultEditor(JComponent.class,
          new ProfileComponentCellEditor());

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 1.0;
        gbc.weightx = 1.0;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.insets = new Insets(COMPONENT_SPACE, COMPONENT_SPACE,
          COMPONENT_SPACE, COMPONENT_SPACE);
        gb.setConstraints(scrollPane, gbc);
        add(scrollPane, gbc);

        JLabel dummy = new JLabel(" ");
        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.gridheight = GridBagConstraints.REMAINDER;
        gbc.weighty = 1.0;
        add(dummy, gbc);
    }

    public void getUpdateInfo(WizardInfo info) {
    }

    private void setLabelCellRenderer(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(
          new DefaultTableCellRenderer());
    }

    private void setLabelCellEditor(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(
          new PasswordCellRenderer());
        table.getColumnModel().getColumn(index).setCellEditor(
          new DefaultCellEditor(new JPasswordField()));
    }
}

