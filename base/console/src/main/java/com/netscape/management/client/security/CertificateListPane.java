/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc.  Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation version
 * 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 * END COPYRIGHT BLOCK **/
package com.netscape.management.client.security;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.KeyEvent;
import java.util.Hashtable;
import java.util.Vector;

import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTable;
import javax.swing.KeyStroke;

import com.netscape.management.client.components.Table;
import com.netscape.management.client.util.Debug;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.Help;
import com.netscape.management.client.util.JButtonFactory;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.nmclf.SuiConstants;

class CertificateListPane extends JPanel implements SuiConstants{

    //protected static int DETAIL      = 1<<0;
    protected static int REQUEST     = 1<<1;
    protected static int RENEW       = 1<<2;
    protected static int INSTALL     = 1<<3;
    protected static int EDITTRUST   = 1<<4;
    protected static int ADD         = 1<<5;
    //protected static int DELETE      = 1<<6;

    ResourceSet resource;
    private Vector certs;

    protected JButton detail, request, renew, install, edittrust, add, delete;

    Help help;

    public CertificateListPane(Vector certs) {
        super();
        setLayout(new GridBagLayout());

        resource = new ResourceSet("com.netscape.management.client.security.securityResource");
        help = new Help(resource);
        this.certs = certs;

    }

    Vector getCerts() {
        return certs;
    }

    void setCerts(Vector certs) {
        this.certs = certs;
    }

    protected String getSelectedCertNickname(JTable table, String columnIdentifier) {
        int selectedRow = table.getSelectedRow();
        int nameColumnIndex = table.getColumn(columnIdentifier).getModelIndex();

        String nickname = "";

        if (selectedRow != -1) {
            nickname = table.getValueAt(selectedRow, nameColumnIndex).toString();
        }

        Debug.println("Selected: "+nickname);

        return nickname;
    }

    /**
     * Return the specified attribute value for the selected certificate
     */
    protected String getSelectedCertAttribute(JTable table, String attrName) {
        String attrValue = "";
        int selectedRow = table.getSelectedRow();

        if (selectedRow >=0  && selectedRow < certs.size()) {
            Hashtable cert = (Hashtable) certs.elementAt(selectedRow);
            if (cert.get(attrName) != null) {
                attrValue = (String)cert.get(attrName);
            }
        }

        Debug.println("Selected " + attrName + "=" + attrValue);

        return attrValue;
    }

    private String i18n(String id) {
        return resource.getString("CertificateDialog", id);
    }

    private String i18n(String id, String arg)
    {
        return resource.getString("CertificateDialog", id, arg);
    }

    public boolean confirmDeleteDialog(String certName)
    {

        //comment out until ErrorDialog is fixed
        /*ErrorDialog errDlg = new ErrorDialog(null,
          i18n("removeCertTitle"),
          i18n("removeCertQuestion", certName),
          null, null,
          ErrorDialog.YES_NO,
          ErrorDialog.NO);
          errDlg.setIcon(ErrorDialog.QUESTION_ICON);
          errDlg.hideDetail();
          errDlg.show();

          return  (errDlg.getButtonClicked()==ErrorDialog.YES);*/

        int answer = JOptionPane.showConfirmDialog(this,
                                                   i18n("removeCertQuestion", certName),
                                                   i18n("removeCertTitle"),
                                                   JOptionPane.YES_NO_OPTION,
                                                   JOptionPane.QUESTION_MESSAGE);

        return (answer == JOptionPane.YES_OPTION);
    }


    //default DETAIL and DELETE will be provided
    public void setContent(Table table, String tableTitle, int buttons) {
        JLabel label = new JLabel(tableTitle);
        label.setLabelFor(table);
        GridBagUtil.constrain(this,
                              label,
                              0, 0, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              VERT_WINDOW_INSET,
                              HORIZ_WINDOW_INSET,
                              VERT_WINDOW_INSET,
                              HORIZ_WINDOW_INSET);

        GridBagUtil.constrain(this, JTable.createScrollPaneForTable(table),
                              0, 1, 1, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0,
                              HORIZ_WINDOW_INSET,
                              VERT_WINDOW_INSET,
                              HORIZ_WINDOW_INSET);

        JPanel buttonPane = new JPanel();
        buttonPane.setLayout(new GridBagLayout());

        ActionListener listener = new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    String command = e.getActionCommand();

                    if (command.equals("DETAIL") ) {
                        CertificateListPane.this.detailInvoked();
                    } else if (command.equals("REQUEST") ) {
                        CertificateListPane.this.requestInvoked();
                    } else if (command.equals("RENEW") ) {
                        CertificateListPane.this.renewInvoked();
                    } else if (command.equals("INSTALL") ) {
                        CertificateListPane.this.installInvoked();
                    } else if (command.equals("EDITTRUST") ) {
                        CertificateListPane.this.edittrustInvoked();
                    } else if (command.equals("ADD") ) {
                        CertificateListPane.this.addInvoked();
                    } else if (command.equals("DELETE") ) {
                        CertificateListPane.this.deleteInvoked();
                    }
                }
            };

        int x = 0;
        Vector buttonList = new Vector();

        detail    = JButtonFactory.create(resource.getString("CertificateListPane", "detailButtonLabel"), listener, "DETAIL");
        detail.setToolTipText(resource.getString("CertificateListPane", "detailButton_tt"));
        GridBagUtil.constrain(buttonPane, detail,
                              x, 0, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.NONE,
                              0, HORIZ_WINDOW_INSET, 0, COMPONENT_SPACE);
        buttonList.addElement(detail);
        detail.registerKeyboardAction(listener, "DETAIL",
                                      KeyStroke.getKeyStroke(KeyEvent.VK_L, 0),
                                      JComponent.WHEN_IN_FOCUSED_WINDOW);

        if ((buttons & REQUEST) == REQUEST) {
            request   = JButtonFactory.create(resource.getString("CertificateListPane", "requestButtonLabel"), listener, "REQUEST");
            request.setToolTipText(resource.getString("CertificateListPane", "requestButton_tt"));
            GridBagUtil.constrain(buttonPane, request,
                                  ++x, 0, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.NORTH, GridBagConstraints.NONE,
                                  0, 0, 0, COMPONENT_SPACE);
            buttonList.addElement(request);
            request.registerKeyboardAction(listener, "REQUEST",
                                           KeyStroke.getKeyStroke(KeyEvent.VK_R, 0),
                                           JComponent.WHEN_IN_FOCUSED_WINDOW);
        }

        if ((buttons & RENEW) == RENEW) {
            renew     = JButtonFactory.create(resource.getString("CertificateListPane", "renewButtonLabel"), listener, "RENEW");
            renew.setToolTipText(resource.getString("CertificateListPane", "renewButton_tt"));
            GridBagUtil.constrain(buttonPane, renew,
                                  ++x, 0, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.NORTH, GridBagConstraints.NONE,
                                  0, 0, 0, COMPONENT_SPACE);
            buttonList.addElement(renew);
            renew.registerKeyboardAction(listener, "RENEW",
                                         KeyStroke.getKeyStroke(KeyEvent.VK_N, 0),
                                         JComponent.WHEN_IN_FOCUSED_WINDOW);
        }

        if ((buttons & INSTALL) == INSTALL) {
            install   = JButtonFactory.create(resource.getString("CertificateListPane", "installButtonLabel"), listener, "INSTALL");
            install.setToolTipText(resource.getString("CertificateListPane", "installButton_tt"));
            GridBagUtil.constrain(buttonPane, install,
                                  ++x, 0, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.NORTH, GridBagConstraints.NONE,
                                  0, 0, 0, COMPONENT_SPACE);
            buttonList.addElement(install);
            install.registerKeyboardAction(listener, "INSTALL",
                                           KeyStroke.getKeyStroke(KeyEvent.VK_I, 0),
                                           JComponent.WHEN_IN_FOCUSED_WINDOW);
        }

        if ((buttons & EDITTRUST) == EDITTRUST) {
            edittrust = JButtonFactory.create(resource.getString("CertificateListPane", "edittrustButtonLabel"), listener, "EDITTRUST");
            edittrust.setToolTipText(resource.getString("CertificateListPane", "edittrustButton_tt"));
            GridBagUtil.constrain(buttonPane, edittrust,
                                  ++x, 0, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.NORTH, GridBagConstraints.NONE,
                                  0, 0, 0, COMPONENT_SPACE);

            buttonList.addElement(edittrust);
            edittrust.registerKeyboardAction(listener, "EDITTRUST",
                                             KeyStroke.getKeyStroke(KeyEvent.VK_T, 0),
                                             JComponent.WHEN_IN_FOCUSED_WINDOW);
        }

        if ((buttons & ADD) == ADD) {
            add       = JButtonFactory.create(resource.getString("CertificateListPane", "addButtonLabel"), listener, "ADD");
            add.setToolTipText(resource.getString("CertificateListPane", "addButton_tt"));
            GridBagUtil.constrain(buttonPane, add,
                                  ++x, 0, 1, 1,
                                  0.0, 0.0,
                                  GridBagConstraints.NORTH, GridBagConstraints.NONE,
                                  0, 0, 0, COMPONENT_SPACE);

            buttonList.addElement(add);
            add.registerKeyboardAction(listener, "ADD",
                                       KeyStroke.getKeyStroke(KeyEvent.VK_A, 0),
                                       JComponent.WHEN_IN_FOCUSED_WINDOW);
        }

        delete    = JButtonFactory.createDeleteButton(listener);
        delete.setToolTipText(resource.getString("CertificateListPane", "deleteButton_tt"));
        buttonList.addElement(delete);

        JButton resizeButtons[] = new JButton[buttonList.size()];
        for (int i=0; i<resizeButtons.length; i++) {
            resizeButtons[i] = (JButton)(buttonList.elementAt(i));
        }
        JButtonFactory.resize(resizeButtons);

        GridBagUtil.constrain(buttonPane, delete,
                              ++x, 0, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.NONE,
                              0, 0, 0, COMPONENT_SPACE);

        GridBagUtil.constrain(buttonPane, Box.createHorizontalGlue(),
                              ++x, 0, 1, 1,
                              1.0 , 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, 0, 0);

        GridBagUtil.constrain(this, buttonPane,
                              0, 2, 1, 1,
                              1.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                              0, 0, VERT_WINDOW_INSET, 0);

    }


    public void detailInvoked() {}
    public void requestInvoked() {}
    public void renewInvoked() {}
    public void installInvoked() {}
    public void edittrustInvoked() {}
    public void addInvoked() {}
    public void deleteInvoked() {}

    public void helpInvoked() {
        help.contextHelp("CertificateDialog", "help");
    }

}
