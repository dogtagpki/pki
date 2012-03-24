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

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

/**
 *
 * Step 3 of the certificate installation under Key & Cert wizard.
 * This pane display to user the certificate taht is about to be installed.
 *
 * @version    1.0    98/07/10
 * @author     shihcm@netscape.com
 *
 */
class CertInstallCertInfoPane extends JPanel implements SuiConstants,
IKeyCertPage {


    JLabel _subjectLabel;
    JLabel _issuerLabel;

    JLabel certName = new JLabel();
    MultilineLabel issuer = new MultilineLabel(6, 5);
    MultilineLabel subject = new MultilineLabel(6, 5);

    MultilineLabel serialNum = new MultilineLabel();
    MultilineLabel valid = new MultilineLabel();
    MultilineLabel fingerprint = new MultilineLabel();
    MultilineLabel addReplaceLabel = new MultilineLabel();
    JButton addReplaceButton = new JButton();

    String certNameLabel;

    /**
     * Reference to a copy of WizardObservable that was pass in via pageShow
     * WizardObservable contain shared information between all the panels
     * under Key & Cert Wizard.
     */
    WizardObservable obs;

    /**
     * Communication module that does the actually sends the cgi request to install
     * the certificate.
     */
    KeyCertTaskInfo taskInfo;


    /**
     * Properties file, contain all the localized string
     */
    ResourceSet resource;

    /**
     * Get the panel that is going to be displayed
     * @return a panel to be displayed by the key & cert wizard
     */
    public JPanel getPanel() {
        return this;
    }

    /**
      * Checks if this panel can be shown
      * @return true if this page can be shown
      */
    public boolean pageShow(WizardObservable observable) {
        obs = observable;
        boolean show =
                ((Boolean)(observable.get("installCert"))).booleanValue();
        if (show) {

            StatusPane statusPane = (StatusPane)(obs.get("statusPane"));
            statusPane.setLastPage(false);

            taskInfo = observable.getTaskInfo();

            Hashtable certInstInfo = (Hashtable)(observable.get("certInstInfo"));
            certInstInfo.put("tokenName", observable.get("tokenName"));

            if (certInstInfo.get("repbutton") != null) {
                try {
                    addReplaceLabel.setText(
                            resource.getString("CertInstallCertInfoPane",
                            "replaceCert"));
                    addReplaceButton.setText(
                            resource.getString("CertInstallCertInfoPane",
                            "replace"));
                } catch (Exception e) {}
            } else {
                try {
                    addReplaceLabel.setText(
                            resource.getString("CertInstallCertInfoPane",
                            "addCert"));
                    addReplaceButton.setText(
                            resource.getString("CertInstallCertInfoPane",
                            "add"));
                } catch (Exception e) {}
            }
            CertInfo certInfo = (CertInfo)(observable.get("certInfo"));

            subject.setText(certInfo.getSubject());
            issuer.setText(certInfo.getIssuer());
            certName.setText(certNameLabel + certInfo.getCertName());
            serialNum.setText(certInfo.getSerialNumber());
            fingerprint.setText(certInfo.getFingerPrint());

            String validFromToLabel = null;
            try {
                validFromToLabel =
                        resource.getString("CertInstallCertInfoPane",
                        "validFromTo");
            } catch (Exception e) {}

            valid.setText( KeyCertUtility.replace(
                    KeyCertUtility.replace(validFromToLabel, "%FROM",
                    certInfo.getValidFrom()), "%TO",
                    certInfo.getValidTo()));



        }
        return show;
    }

    /**
      * Checks if this panel can be hidden
      * @return true if this page can be hide
      */
    public boolean pageHide(WizardObservable observable) {
        return true;
    }


    /**
      *
      * Inner class to handle add/replace certificate.
      * If add/replace action occure method within this inner
      * class will call the cgi to do the work.
      *
      */
    class CertInfoActionListener implements ActionListener {
        public void actionPerformed(ActionEvent event) {
            if (event.getActionCommand().equals("add_replace")) {
                Hashtable certInstInfo = (Hashtable)(obs.get("certInstInfo"));
                Enumeration keys = certInstInfo.keys();
                while (keys.hasMoreElements()) {
                    String key = (String)(keys.nextElement());
                    taskInfo.put(key, certInstInfo.get(key));
                }

                try {
                    taskInfo.put("keyfilepw", obs.get("keyfilepw"));
                    taskInfo.exec(taskInfo.SEC_ICRT);
                    taskInfo.clear();
                } catch (Exception e) {
                    SuiOptionPane.showMessageDialog(
                            UtilConsoleGlobals.getActivatedFrame(),
                            e.getMessage());
                    //((IWizardControl)(obs.get("Wizard"))).cancelInvoked();
                    return;
                }

                Vector messages = taskInfo.getResponse().getMessages();
                //int nMessages = messages.size();

                StatusPane statusPane = (StatusPane)(obs.get("statusPane"));
                statusPane.setMessage(messages);
                statusPane.setShow(true);
                statusPane.setLastPage(true);

                ((IWizardControl)(obs.get("Wizard"))).setIsLastPage(false);
                ((IWizardControl)(obs.get("Wizard"))).setCanGoForward(
                        false);
                ;
                ((IWizardControl)(obs.get("Wizard"))).nextInvoked();
            }
        }
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

        addReplaceButton.setActionCommand("add_replace");
        addReplaceButton.addActionListener(new CertInfoActionListener());

        GridBagUtil.constrain(subjectIssuerPane, _subjectLabel, 0, 0,
                1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(subjectIssuerPane, _issuerLabel, 2, 0, 1,
                1, 1.0, 0.0, GridBagConstraints.NORTH,
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
                GridBagConstraints.BOTH, 0, 0, 0, 0);

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
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        return subjectIssuerPane;
    }


    /**
      *
      * A panel contain a string telling user whether a add or a replace can
      * take place for this certificate
      * [panel]
      *    [string telling use if they can add or replace]  [add|replace button]
      * [panel]
      *
      */
    private JPanel getAddReplacePane() {
        JPanel addReplacePane = new JPanel();
        addReplacePane.setLayout(new GridBagLayout());

        GridBagUtil.constrain(addReplacePane, addReplaceLabel, 0, 0, 1,
                1, 1.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(addReplacePane, addReplaceButton, 1, 0,
                1, 1, 1.0, 0.0, GridBagConstraints.EAST,
                GridBagConstraints.NONE, 0, 0, 0, 0);

        return addReplacePane;
    }

    /**
      *
      * This panel contain certificate informations, serial number, finger print,
      * validation date.  Also make a cal to getSubjectIssuerPanel() to obtain
      * subject and issuer ui
      * [panel]
      *    [subject]     [issuer]
      *    [serial number[
      *    [finger print]
      *    [validation]
      * [panel]
      *
      */
    private JPanel getInfoPane() {
        JPanel infoPane = new JPanel();
        infoPane.setLayout(new GridBagLayout());

        int y = 0;

        GridBagUtil.constrain(infoPane, certName, 0, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);


        GridBagUtil.constrain(infoPane, getSubjectIssuerPane(), 0, ++y,
                1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0,
                SEPARATED_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(infoPane,
                new JLabel( resource.getString("CertInstallCertInfoPane",
                "serialLabel")), 0, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        GridBagUtil.constrain(infoPane, serialNum, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(infoPane,
                new JLabel( resource.getString("CertInstallCertInfoPane",
                "fingerprintLabel")), 0, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        GridBagUtil.constrain(infoPane, fingerprint, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(infoPane, valid, 0, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        return infoPane;
    }



    /**
      *
      * Constructor, create a certificate information pane and a action button allow
      * user to add or replace certificate.
      *
      */
    public CertInstallCertInfoPane() {
        super();
        setLayout(new GridBagLayout());

        resource = KeyCertUtility.getKeyCertWizardResourceSet();

        certNameLabel = resource.getString("CertInstallCertInfoPane", "certNameLabel");

        _subjectLabel = new JLabel(
                resource.getString("CertInstallCertInfoPane", "subjectLabel"));
        _issuerLabel = new JLabel(
                resource.getString("CertInstallCertInfoPane", "issuerLabel"));


        setBorder( new TitledBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)),
                resource.getString("CertInstallCertInfoPane", "title")));

        int y = 0;

        GridBagUtil.constrain(this, getInfoPane(), 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(this, Box.createVerticalGlue(), 0, ++y,
                1, 1, 1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(this, getAddReplacePane(), 0, ++y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);
    }

    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     f.getContentPane().add("North", new CertInstallCertInfoPane());
     f.setSize(400,400);
     f.show();
     }*/

}
