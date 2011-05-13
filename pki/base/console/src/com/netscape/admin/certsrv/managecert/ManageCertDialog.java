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
package com.netscape.admin.certsrv.managecert;

import java.util.*;
import java.awt.*;
import java.awt.event.*;
import javax.swing.table.*;
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.admin.certsrv.*;
import com.netscape.management.client.util.*;
import com.netscape.admin.certsrv.connection.*;
import com.netscape.certsrv.common.*;

/**
 * This class lists out all the CA certificates from the internal token.
 * 
 * @author chrisho
 * @version $Revision$, $Date$
 * @see com.netscape.admin.certsrv.managecert
 */
public class ManageCertDialog extends JDialog implements ActionListener,
  MouseListener {
    private static final String PANELNAME = "MANAGECERTDIALOG";
    static final Dimension DEFAULT_SIZE = new Dimension(460,500);
    static final Dimension BUTTON_MIN_SIZE = new Dimension(100,30);

    protected ResourceBundle mResource;
    private JFrame  mParent;
    private JTable mTable;
    private ManageCertModel mDataModel;
    private JButton mClose, mDelete, mEdit, mHelp;
    private AdminConnection mConn;
    private static final String HELPINDEX = 
      "configuration-managecert-wizard-certlists-help";

    public ManageCertDialog(JFrame parent) {
        super(parent, true);
        mParent = parent;
        setSize(460,500);
        getRootPane().setDoubleBuffered(true);
        setLocationRelativeTo(parent);
        mResource = ResourceBundle.getBundle(CMSAdminResources.class.getName());
        setTitle(mResource.getString(PANELNAME+"_TITLE"));
        setDisplay();
    }

    public void showDialog(AdminConnection conn) {
        mConn = conn;
        refresh();
        this.show();
    }

    private void refresh() {
        NameValuePairs response=null;
        try {
            response = mConn.search(DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_ALL_CERTLIST,
              new NameValuePairs());
        } catch (EAdminException e) {
            CMSAdminUtil.showErrorDialog(mParent, mResource, e.toString(),
              CMSAdminUtil.ERROR_MESSAGE);
        }

		if (response == null) { /* we must have gotten timed out */
			return;
		}

        mDataModel.removeAllRows();

        String[] vals = new String[response.size()];
        int i=0;
        for (Enumeration e = response.getNames(); e.hasMoreElements() ;) {
            String entry = ((String)e.nextElement()).trim();
            vals[i++] = entry;
        }

        CMSAdminUtil.bubbleSort(vals);

        for (i=0; i<vals.length; i++) { 
            String entry = vals[i];
            String value = response.getValue(entry);
            addRows(entry, value);
        }
        mTable.getSelectionModel().clearSelection();
        setButtons();
    }

    private void addRows(String entry, String value) {
        StringTokenizer tokenizer = new StringTokenizer(value, ";");
        int numTokens = tokenizer.countTokens();
        while (tokenizer.hasMoreTokens()) {
            String token = (String)tokenizer.nextToken();
            String expiredDate = token.substring(0, token.length()-2);
            String trust = token.substring(token.length()-1);
            Vector v = new Vector();
            v.addElement(entry);
            v.addElement(expiredDate);
            if (trust.equals("T"))
                v.addElement("Trusted");
            else if (trust.equals("U"))
                v.addElement("Untrusted");
			else if (trust.equals("u"))
				v.addElement("N/A");
            mDataModel.addRow(v);
        }
    }

    private void setDisplay() {
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
		gbc.fill = gbc.BOTH;
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

    public JPanel makeActionPane() {
        JPanel panel = new JPanel();
        
        mClose = new JButton();
        mClose.setText(mResource.getString(
          "MANAGECERTDIALOG_BUTTON_CLOSE_LABEL"));
        mClose.addActionListener(this);

        mEdit = new JButton();
        mEdit.setText(mResource.getString(
          "MANAGECERTDIALOG_BUTTON_EDIT_VIEW_LABEL"));
        mEdit.addActionListener(this);

        mDelete = new JButton();
        mDelete.setText(mResource.getString(
          "MANAGECERTDIALOG_BUTTON_DELETE_LABEL"));
        mDelete.addActionListener(this);

        mHelp = new JButton();
        mHelp.setText(mResource.getString(
          "MANAGECERTDIALOG_BUTTON_HELP_LABEL"));
        mHelp.addActionListener(this);

        //JButton[] buttons = {mClose, mEdit, mDelete, mHelp};
        JButton[] buttons = {mClose, mEdit, mDelete};
        return CMSAdminUtil.makeJButtonPanel(buttons, true);
    }

    public JPanel makeContentPane() {
        JPanel content = new JPanel();
        content.setBorder(CMSAdminUtil.makeTitledBorder(mResource, 
          "MANAGECERTDIALOG", "CERT"));
        GridBagLayout gb = new GridBagLayout();
        GridBagConstraints gbc = new GridBagConstraints();
        content.setLayout(gb);

        CMSAdminUtil.resetGBC(gbc);
        mDataModel = new ManageCertModel();
        mTable = new JTable(mDataModel);
        JScrollPane scrollPane = JTable.createScrollPaneForTable(mTable);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        mTable.setPreferredScrollableViewportSize(new Dimension(200, 350));
        mTable.setAutoscrolls(true);
        mTable.sizeColumnsToFit(true);
        mTable.addMouseListener(this);
        scrollPane.setBackground(Color.white);
        setLabelCellRenderer(mTable, 0);
        setLabelCellRenderer(mTable, 1);
        setLabelCellRenderer(mTable, 2);

        CMSAdminUtil.resetGBC(gbc);
        gbc.anchor = gbc.NORTH;
        gbc.gridwidth = gbc.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = gbc.BOTH;
        gbc.gridheight = gbc.REMAINDER;
        gbc.insets = new Insets(CMSAdminUtil.COMPONENT_SPACE, 
          CMSAdminUtil.COMPONENT_SPACE,
          CMSAdminUtil.COMPONENT_SPACE, CMSAdminUtil.COMPONENT_SPACE);
        gb.setConstraints(scrollPane, gbc);
        content.add(scrollPane);

        return content;
    }

    protected void setLabelCellRenderer(JTable table, int index) {
        table.getColumnModel().getColumn(index).setCellRenderer(
          new DefaultTableCellRenderer());
    }

    public void actionPerformed(ActionEvent e) {
        Object source = e.getSource();
        if (source.equals(mClose)) {
            this.hide();
            this.dispose();
        } else if (source.equals(mDelete)) {
            try {
				// make sure selected cert is not a user cert
				boolean userCert = false;
				int[] rows = mTable.getSelectedRows();
				for (int i=0; i<rows.length; i++) {
					String trust =
						(String)mDataModel.getValueAt(rows[i], 2);
					if (trust.equals("N/A")) {
						userCert = true;
					}

					String value = (String)mDataModel.getValueAt(rows[i], 0);
					if (
						 (value.indexOf(Constants.PR_CA_SIGNING_NICKNAME) != -1) || (value.indexOf(Constants.PR_OCSP_SIGNING_CERT) != -1) ) {
						userCert = true;
					}
				}

				if (userCert == false) {
					NameValuePairs nvps = getCerts();
					mConn.modify(DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_DELETE_CERTS,
								 Constants.RS_ID_CONFIG, nvps);
					refresh();
				} else {
					// user certs can't be removed from here
					CMSAdminUtil.showErrorDialog(mParent, mResource,
								mResource.getString("CERTIMPORTDIALOG_DIALOG_CANTDELETE_MESSAGE"),
							 CMSAdminUtil.ERROR_MESSAGE);
				}
            } catch (EAdminException ex) {
                CMSAdminUtil.showErrorDialog(mParent, mResource, ex.toString(),
                  CMSAdminUtil.ERROR_MESSAGE);
            }
        } else if (source.equals(mEdit)) {
            displayCert();
        } else if (source.equals(mHelp)) {
            CMSAdminUtil.help(HELPINDEX);
        }
    }

    private void displayCert() {
            try {
                NameValuePairs nvps = getCerts();
                NameValuePairs results = mConn.process(
                  DestDef.DEST_SERVER_ADMIN, ScopeDef.SC_CERT_PRETTY_PRINT,
                  Constants.RS_ID_CONFIG, nvps);
                if (nvps.size() <= 0)
                    return;
                NameValuePair nvp = results.elementAt(0);
                String name = nvp.getName();
                String print = nvp.getValue();
                CertificateInfoDialog dialog = new CertificateInfoDialog(mParent);
                dialog.showDialog(name, print, getTrustLbl(), getDate(),mConn);
                refresh();
            } catch (EAdminException ex) {
                CMSAdminUtil.showErrorDialog(mParent, mResource, ex.toString(),
                  CMSAdminUtil.ERROR_MESSAGE);
            }
    }

    //==== MOUSELISTENER ======================
    public void mouseClicked(MouseEvent e) {
        setButtons();

        //we track the double click action on the table entry - View op
        if(mTable.getSelectedRow() >= 0) {
            if(e.getClickCount() == 2) {
                displayCert();
            }
        }
    }

    public void mouseReleased(MouseEvent e) {
    }

    public void mousePressed(MouseEvent e) {
    }

    public void mouseEntered(MouseEvent e) {
    }

    public void mouseExited(MouseEvent e) {
    }

    private void setButtons() {
        //enable and disable buttons accordingly
        if (mTable.getSelectionModel().isSelectionEmpty()) {
            mDelete.setEnabled(false);
            mEdit.setEnabled(false);
            return;
        }

        if(mDataModel.getRowCount()< 0) {
            mDelete.setEnabled(false);
            mEdit.setEnabled(false);
            return;
        }

        mDelete.setEnabled(true);
        mEdit.setEnabled(true);
    }

    private NameValuePairs getCerts() {
        int[] rows = mTable.getSelectedRows();
        NameValuePairs nvps = new NameValuePairs();
        String name = "certName";
        for (int i=0; i<rows.length; i++) {
            String value = (String)mDataModel.getValueAt(rows[i], 0);
            String date = (String)mDataModel.getValueAt(rows[i], 1);
            nvps.add(name+i, value+";"+date);
        }
        return nvps;
    }

    private String getTrustLbl() {
        int row = mTable.getSelectedRow();
        String trust = (String)mDataModel.getValueAt(row, 2);
        if (trust.equals("Trusted"))
            return "Trust";
        else if (trust.equals("Untrusted"))
            return "Untrust";
		else if (trust.equals("N/A"))
			return "N/A";
		else
			return "Unknown";

    }

    private String getDate() {
        int row = mTable.getSelectedRow();
        return (String)mDataModel.getValueAt(row, 1);
    }
}
