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

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.Vector;

import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

import com.netscape.admin.certsrv.CMSAdminResources;
import com.netscape.admin.certsrv.CMSAdminUtil;
import com.netscape.admin.certsrv.EAdminException;
import com.netscape.admin.certsrv.connection.AdminConnection;
import com.netscape.certsrv.common.Constants;
import com.netscape.certsrv.common.DestDef;
import com.netscape.certsrv.common.NameValuePairs;
import com.netscape.certsrv.common.ScopeDef;

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
        this.setVisible(true);
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
        for (String entry : response.keySet()) {
            vals[i++] = entry.trim();
        }

        CMSAdminUtil.bubbleSort(vals);

        for (i=0; i<vals.length; i++) {
            String entry = vals[i];
            String value = response.get(entry);
            addRows(entry, value);
        }
        mTable.getSelectionModel().clearSelection();
        setButtons();
    }

    private void addRows(String entry, String value) {
        StringTokenizer tokenizer = new StringTokenizer(value, ";");
        int numTokens = tokenizer.countTokens();
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken();
            String expiredDate = token.substring(0, token.length()-2);
            String trust = token.substring(token.length()-1);
            Vector<Object> v = new Vector<>();
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
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
		gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
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
        JScrollPane scrollPane = new JScrollPane(mTable);
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
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridheight = GridBagConstraints.REMAINDER;
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
            this.setVisible(false);
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
                String name = results.keySet().iterator().next(); // first element
                String print = results.get(name);
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
            nvps.put(name + i, value + ";" + date);
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
