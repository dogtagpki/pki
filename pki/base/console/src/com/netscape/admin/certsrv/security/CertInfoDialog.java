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
package com.netscape.admin.certsrv.security;

import javax.swing.*;
import javax.swing.border.*;

import java.awt.*;
import java.awt.event.*;
import java.util.*;

import com.netscape.management.client.console.ConsoleInfo;


import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

/**
 *
 * UI to display subject and issuer of the certificate, and
 * allow user to change trust, delete, or view detail information
 * of this certificate
 *
 * @version    1.0    98/07/10
 * @author     shihcm@netscape.com
 * @see com.netscape.admin.certsrv.security.CertDetailInfoDialog
 * @see com.netscape.admin.certsrv.security.CertInfo
 *
 */
class CertInfoDialog extends AbstractDialog implements SuiConstants {


    /**
     * String for trust and none trusted status of the certificate
     * String is localized and will be retrived from the properties file
     */
    String trustString, notTrustString;

    /**
     * Task info, the communication channel that calls the server to execute the cgi
     */
    KeyCertTaskInfo _taskInfo;


    /**
     * Certificate information, certificate info used to populate this gui
     */
    CertInfo _certInfo;

    /**
     * cn of the sie.  ie.  admin-serv-buddha
     * Note that the key & cert db file are named using the sie.
     */
    String alias;

    /**
     * Properties file, contain all the localized string
     */
    ResourceSet resource = new ResourceSet("com.netscape.admin.certsrv.security.CertManagementResource");

    /**
     * After this dilaog is disposed, the routine(CertManagementDialog) that opens this ui will
     * need to know whether the cert presented has been deleted and update it's gui accordingly.
     */
    static boolean delete = false;

    /**
     * Owner of this dialog
     */
    JFrame _parent;

    JLabel certName = new JLabel();
    MultilineLabel issuer = new MultilineLabel(6, 5);
    MultilineLabel subject = new MultilineLabel(6, 5);

    JButton bDetail;
    JButton bDelete;
    JButton bTrust;

    JLabel _issuerLabel;
    JLabel _subjectLabel;

    /**
     * Trust status of the cert that is presented
     */
    boolean trustedCert;


    private boolean promptBeforeDelete() {
        return SuiOptionPane.showConfirmDialog(this,
                resource.getString("CertInfoDialog", "areYouSure"),
                resource.getString("CertInfoDialog", "confirmTitle"),
                SuiOptionPane.YES_NO_OPTION) == SuiOptionPane.YES_OPTION;
    }

    private void deleteSuccess() {
        SuiOptionPane.showMessageDialog(this,
                resource.getString("CertInfoDialog", "certDeleted"));
    }

    /**
      *
      * Inner class, where all the action will execute.
      * 3 action can be taken on the certificate: Detail, Delete, [Trust|Reject]
      *
      * Detail:  vew other certificate information that is not currently been
      *          displayed by this dialog
      * Delete:  Delete certificate from the certificate database
      * Trust:   Change the certificate's trust status to trust
      * Reject:  Change the certificate's trust status to do not trust
      *
      * @see com.netscape.admin.certsrv.security.CertDetailInfoDialog
      */
    class CertInfoActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            delete = false;

            if (_taskInfo == null) {
                if (e.getActionCommand().equals("CLOSE")) {
                    CertInfoDialog.this.closeInvoked();
                } else if (e.getActionCommand().equals("DELETE")) {
                    if (promptBeforeDelete()) {
                        deleteSuccess();
                        delete = true;
                        setVisible(false);
                    }
                } else if (e.getActionCommand().equals("HELP")) {
                    helpInvoked();
                }

            } else {
                if (e.getActionCommand().equals("DETAIL")) {
                    (new CertDetailInfoDialog(_parent, _certInfo)).show();
                } else if (e.getActionCommand().equals("DELETE")) {
                    if (!promptBeforeDelete()) {
                        return;
                    }
                    //call delete cert cgi
                    _taskInfo.clear();
                    _taskInfo.put("certnn", _certInfo.getCertName());
                    _taskInfo.put("formop", "D");
                    _taskInfo.put("alias", alias);
                    Response response = null;
                    try {
                        response = _taskInfo.exec(_taskInfo.SEC_ECRT);
                    } catch (Exception error) {
                        SuiOptionPane.showMessageDialog(
                                UtilConsoleGlobals.getActivatedFrame(),
                                error.getMessage());
                        return;
                    }

                    //if (response.hasCertInfo()) {
                    if (!(((Message)(response.getMessages().elementAt(0))).
                            isFailure())) {
                        deleteSuccess();
                        delete = true;
                        setVisible(false);
                    } else {
                        try {
                            MessageDialog.messageDialog( (Message)
                                    (response.getMessages().elementAt(0)));
                        } catch (Exception e2) {
                            //shouldn't even be here in the first place.  if cgi fail or return nothing
                            //then it should be handle right after KeyCertTaskInfo.exec(...) is called
                            //If exception occure here here then something is really mess up
                            Debug.println("Error in decoding server messages");
                        }
                    }
                }
                else if (e.getActionCommand().equals("TRUST")) {
                    //call trust cert cgi
                    //need to display a warning message first
                    _taskInfo.clear();
                    _taskInfo.put("certnn", _certInfo.getCertName());
                    _taskInfo.put("formop", "C");
                    _taskInfo.put("alias", alias);
                    Response response = null;
                    try {
                        response = _taskInfo.exec(_taskInfo.SEC_ECRT);
                    } catch (Exception error2) {
                        SuiOptionPane.showMessageDialog(
                                UtilConsoleGlobals.getActivatedFrame(),
                                error2.getMessage());
                        return;
                    }
                    /*if (response.hasCertInfo()) {
                       setCertInfo(response.getCertInfo());
                       }*/

                    try {
                        if (!(((Message)
                                (response.getMessages().elementAt(0))).
                                isFailure())) {
                            trustedCert = !trustedCert;
                            bTrust.setText(trustedCert ?
                                    resource.getString("CertInfoDialog",
                                    "reject") :
                                    resource.getString("CertInfoDialog",
                                    "trust"));
                        }

                        MessageDialog.messageDialog( (Message)
                                (response.getMessages().elementAt(0)));
                    } catch (Exception e3) {
                        //shouldn't even be here in the first place.  if cgi fail or return nothing
                        //then it should be handle right after KeyCertTaskInfo.exec(...) is called
                        //If exception occure here here then something is really mess up.
                        Debug.println("Error in decoding server messages");
                    }
                }
            }
        }
    }

    /**
      *
      * Update certificate information.
      * Without disposing the dialog this method allows the reuse the the same dialog
      * by repopulating it with new certificate information
      *
      * @param certInfo  contain certificate information to be displayed
      *
      */
    void setCertInfo(CertInfo certInfo) {
        _certInfo = certInfo;

        certName.setText(certInfo.getCertName());
        issuer.setText(certInfo.getIssuer());
        subject.setText(certInfo.getSubject());

        if (_taskInfo != null) {
            trustedCert = certInfo.trusted();
            bTrust.setText(trustedCert ?
                    resource.getString("CertInfoDialog", "reject") :
                    resource.getString("CertInfoDialog", "trust"));
        }
    }


    /**
      *
      * Invoke on-line help
      *
      */
    protected void helpInvoked() {
        Help help = new Help(resource);
        help.help("CertInfoDialog", "help");
    }

    protected void closeInvoked() {
        super.closeInvoked();
    }


    /**
      *
      * @return a panel contain subject and issuer
      *
      * [Panel]
      *     [Subject]     [Issuer]
      * [Panel]
      *
      */
    private JPanel getSubjectIssuerPane() {
        JPanel subjectIssuerPane = new JPanel();
        subjectIssuerPane.setLayout(new GridBagLayout());

        _issuerLabel =
                new JLabel(resource.getString("CertInfoDialog", "issuer"));
        _subjectLabel =
                new JLabel(resource.getString("CertInfoDialog", "subject"));

        //issuer.getCaret().setVisible(false);
        //issuer.setSelectionColor(issuer.getBackground());
        //issuer.setEditable(false);
        //subject.getCaret().setVisible(false);
        //subject.setSelectionColor(issuer.getBackground());
        //subject.setEditable(false);

        GridBagUtil.constrain(subjectIssuerPane, _subjectLabel, 0, 0,
                1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(subjectIssuerPane, _issuerLabel, 2, 0, 1,
                1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(subjectIssuerPane,
                Box.createRigidArea(new Dimension(COMPONENT_SPACE, 0))
                , 1, 1, 1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.NONE, 0, 0, 0, 0);

        JScrollPane subjectScrollPane = new JScrollPane(subject,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        subjectScrollPane.setBorder(
                new CompoundBorder(UITools.createLoweredBorder(),
                new EmptyBorder(VERT_COMPONENT_INSET,
                HORIZ_COMPONENT_INSET, VERT_COMPONENT_INSET,
                HORIZ_COMPONENT_INSET)));
        GridBagUtil.constrain(subjectIssuerPane, subjectScrollPane, 0,
                1, 1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        JScrollPane issuerScrollPane = new JScrollPane(issuer,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        issuerScrollPane.setBorder(
                new CompoundBorder(UITools.createLoweredBorder(),
                new EmptyBorder(VERT_COMPONENT_INSET,
                HORIZ_COMPONENT_INSET, VERT_COMPONENT_INSET,
                HORIZ_COMPONENT_INSET)));
        GridBagUtil.constrain(subjectIssuerPane, issuerScrollPane, 2,
                1, 1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        return subjectIssuerPane;
    }

    /**
      *
      * @return a panel contain certificate name and what ever was return by getSubjectIssuerPane()
      * [PANEL]
      *    Certificate Name
      *    getSubjectIssuerPane()
      * [PANEL]
      *
      * @see #getSubjectIssuerPane
      */
    private JPanel getInfoPane() {
        JPanel infoPane = new JPanel();
        infoPane.setLayout(new GridBagLayout());

        int y = 0;


        GridBagUtil.constrain(infoPane, certName, 0, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                COMPONENT_SPACE, 0, COMPONENT_SPACE, 0);


        GridBagUtil.constrain(infoPane, getSubjectIssuerPane(), 0, ++y,
                1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        return infoPane;
    }



    /**
      *
      * @return Panel contain a row of button(Delete, View, [Trust|Reject])
      * [PANEL]
      *    [bDetail]  [bDelete]   [bTrust|bReject]
      * [PANEL]
      *
      */
    private JPanel getControlPane() {

        JPanel controlPane = new JPanel();
        controlPane.setLayout(new GridBagLayout());
        CertInfoActionListener listener = new CertInfoActionListener();

        if (_taskInfo == null) {

            GridBagUtil.constrain(controlPane,
                    JButtonFactory.createCloseButton(listener), 0, 0,
                    1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                    GridBagConstraints.BOTH,
                    DIFFERENT_COMPONENT_SPACE, 0, 0, COMPONENT_SPACE);

            GridBagUtil.constrain(controlPane,
                    JButtonFactory.create(
                    resource.getString("CertInfoDialog", "delete"),
                    listener, "DELETE"), 1, 0, 1, 1, 1.0, 0.0,
                    GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                    DIFFERENT_COMPONENT_SPACE, 0, 0, COMPONENT_SPACE);

            GridBagUtil.constrain(controlPane,
                    JButtonFactory.createHelpButton(listener), 2, 0,
                    1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                    GridBagConstraints.BOTH,
                    DIFFERENT_COMPONENT_SPACE, 0, 0, 0);
        } else {
            JPanel certButtonPane = new JPanel();
            //certButtonPane.setLayout(new BoxLayout(certButtonPane, BoxLayout.X_AXIS));
            certButtonPane.setLayout(new GridBagLayout());

            certButtonPane.setBorder( new TitledBorder(
                    new CompoundBorder(new EtchedBorder(),
                    new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                    COMPONENT_SPACE, COMPONENT_SPACE)),
                    resource.getString("CertInfoDialog", "certificate")));

            bDetail = JButtonFactory.create(
                    resource.getString("CertInfoDialog", "detail"));
            bDetail.addActionListener(listener);
            bDetail.setActionCommand("DETAIL");

            bDelete = JButtonFactory.create(
                    resource.getString("CertInfoDialog", "delete"));
            bDelete.addActionListener(listener);
            bDelete.setActionCommand("DELETE");

            JButtonFactory.resizeGroup(bDetail, bDelete);

            setTitle(resource.getString("CertInfoDialog", "certificate"));

            //certButtonPane.add(bDetail);
            //certButtonPane.add(Box.createRigidArea(new Dimension(COMPONENT_SPACE, 0)));
            //certButtonPane.add(bDelete);
            GridBagUtil.constrain(certButtonPane, bDetail, 0, 0, 1, 1,
                    1.0, 0.0, GridBagConstraints.WEST,
                    GridBagConstraints.BOTH, 0, 0, 0, 0);
            GridBagUtil.constrain(certButtonPane, bDelete, 1, 0, 1, 1,
                    1.0, 0.0, GridBagConstraints.EAST,
                    GridBagConstraints.BOTH, 0, COMPONENT_SPACE, 0, 0);

            JPanel trustCAButtonPane = new JPanel();
            trustCAButtonPane.setLayout(new GridBagLayout());
            trustCAButtonPane.setBorder( new TitledBorder(
                    new CompoundBorder(new EtchedBorder(),
                    new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                    COMPONENT_SPACE, COMPONENT_SPACE)),
                    resource.getString("CertInfoDialog", "trustCA")));



            bTrust = JButtonFactory.create(
                    resource.getString("CertInfoDialog", "reject"));
            bTrust.addActionListener(listener);
            bTrust.setActionCommand("TRUST");

            JButtonFactory.resizeGroup(bTrust,
                    JButtonFactory.create(
                    resource.getString("CertInfoDialog", "reject")));

            //trustCAButtonPane.add(bTrust);
            GridBagUtil.constrain(trustCAButtonPane, bTrust, 0, 0, 1,
                    1, 1.0, 0.0, GridBagConstraints.WEST,
                    GridBagConstraints.BOTH, 0, 0, 0, 0);

            GridBagUtil.constrain(controlPane, certButtonPane, 0, 0, 1,
                    1, 1.0, 0.0, GridBagConstraints.NORTH,
                    GridBagConstraints.BOTH, 0, 0, 0, 0);

            GridBagUtil.constrain(controlPane, trustCAButtonPane, 1, 0,
                    1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                    GridBagConstraints.BOTH, 0, 0, 0, 0);
        }

        return controlPane;
    }


    void init(CertInfo certInfo) {
        JPanel mainPane = new JPanel();
        mainPane.setBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)));
        mainPane.setLayout(new BorderLayout());

        mainPane.add("Center", getInfoPane());

        if (_taskInfo == null) {
            getContentPane().add("South", getControlPane());
        } else {
            mainPane.add("South", getControlPane());
        }

        getContentPane().add(mainPane);

        setCertInfo(certInfo);

        pack();
        setMinimumSize(getSize());
        setResizable(false);
    }

    /**
      *
      * Construct a certificate information dialog
      *
      * @param parent    the owner of the dialog
      * @param certInfo  contain certificate information to be displayed
      * @param taskInfo  task module that carry out the action for change trust, delete, or get certificate information
      *
      */
    public CertInfoDialog(JFrame parent, CertInfo certInfo,
            KeyCertTaskInfo taskInfo) {
        super(parent, "", true, CLOSE | HELP);

        _taskInfo = taskInfo;
        _parent = parent;

        alias = (String)(taskInfo.get("alias"));

        init(certInfo);
    }

    public CertInfoDialog(JFrame parent, CertInfo certInfo) {
        super(parent, "", true/*, CLOSE | HELP*/);

        _parent = parent;

        init(certInfo);
    }
}

