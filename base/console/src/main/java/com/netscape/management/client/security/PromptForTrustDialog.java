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

import com.netscape.management.nmclf.SuiConstants;
import com.netscape.management.client.util.*;


import java.awt.event.*;
import java.awt.*;
import javax.swing.*;
import java.io.*;
import java.net.*;
import java.security.cert.X509Certificate;

import org.mozilla.jss.ssl.SSLCertificateApprovalCallback.ValidityStatus;

/**
 * Dialog box that prompts user to either accept or reject
 * an untrusted certificate.
 */
public class PromptForTrustDialog extends AbstractDialog implements SuiConstants {

    private static boolean certIsAccepted = false;
    private static boolean acceptedForSingleSession = false;

    private UserConfirmationActionListener buttonActionListener =
            new UserConfirmationActionListener();
    static ResourceSet _resource = new ResourceSet("com.netscape.management.client.security.ServerAuthResource");

    ViewCertificateDialog viewCertDialog;
    JCheckBox oneSession;


    /**
     * create a dialog that prompt user to either accept or reject an untrusted certificate
     * @param parent             the owner of the dialog
     * @param cert               certificate chain
     * @param certChain_errCode  cert chain errors (0 if no errors)
     * @param serverCert_errCode server cert errors (0 if no errors)
     *
     *
     */
    public PromptForTrustDialog(Frame parent, X509Certificate cert,
            ValidityStatus status) {
        super(parent, "", true);

        setTitle(_resource.getString("PromptForTrustDialog", "title"));

        getContentPane().setLayout(new GridBagLayout());


        //Add action button pane first so the accept button will
        //get default focus.  Already try various way with *Focus() call
        //none of them work.
        GridBagUtil.constrain(getContentPane(), createActionButtons(),
                0, 1, 1, 1, 0.0, 0.0, GridBagConstraints.SOUTHEAST,
                GridBagConstraints.NONE, 0, 0, 0, 0);

        GridBagUtil.constrain(getContentPane(), siteAlert(), 0, 0, 1,
                1, 1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, VERT_WINDOW_INSET,
                VERT_WINDOW_INSET, 0, 0);

        viewCertDialog = new ViewCertificateDialog(parent, cert, status);

        setMinimumSize(400, 250);
        if (parent == null) {
            ModalDialogUtil.setCenteredDialog(this);
        }
        // We need to call pack() twice to get the JTextArea we use to display at
        // the right size.  See http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4446522
        // for more details.
        pack();
        pack();
    }


    /**
      * Handles all the action (Ok, Accept, Reject, and Help)
      *
      */
    class UserConfirmationActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            if (e.getActionCommand().equals("ACCEPT")) {
                certIsAccepted = true;
                setVisible(false);
            } else if (e.getActionCommand().equals("REJECT")) {
                certIsAccepted = false;
                setVisible(false);
            } else if (e.getActionCommand().equals("VIEWCERT")) {
                viewCertDialog.show();
            } else if (e.getActionCommand().equals("HELP")) {
                String urlString = _resource.getString("PromptForTrustDialog", "help");
                if (urlString.length()>0) {
                    //one level up to the <sr> instead of <sr>/java
                    File f = new File("..");
                    
                    try {
                        URL url = f.toURL();
                    
                        Browser browser = new Browser();
                        browser.open(url.toString()+urlString,  Browser.EXISTING_WINDOW);
                    } catch (Exception urlError) {
                        SecurityUtil.printException("PromptForTrustDialog", urlError);
                    }
                }
            }
        }
    }


    /**
      * @return true if certificate is accepted
      */
    public boolean isCertAccepted() {
        return certIsAccepted;
    }

    /**
      * @return true certificate should only be accept for a single session
      */
    public boolean isAcceptedForOneSession() {
        return oneSession.isSelected();
    }


    /**
      * Allow reuse of this dialog, if it is not disposed.
      * @param cert               certificate chain
      * @param certChain_errCode  cert chain errors (0 if no errors)
      * @param serverCert_errCode server cert errors (0 if no errors)
      *
      */
    public void setCertificateInfo(X509Certificate cert,
                                   ValidityStatus status) {
        viewCertDialog.setCertificate(cert, status);
        //oneSession.setSelected(false);
     }


    /**
      * Create a warning message panel
      */
    private JPanel siteAlert() {
        JPanel notTrustedSiteWarning = new JPanel();
        notTrustedSiteWarning.setLayout(new GridBagLayout());

        JLabel warningImage = new JLabel(UIManager.getIcon("OptionPane.warningIcon"));
        MultilineLabel warningMsg = new MultilineLabel(
                _resource.getString("PromptForTrustDialog", "warningMessage"));
        oneSession = new JCheckBox(
                _resource.getString("PromptForTrustDialog", "acceptForOneSession"));

        GridBagUtil.constrain(notTrustedSiteWarning, warningImage, 0,
                0, 1, 1, 0.0, 0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.NONE, 0, 0, 0,
                DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(notTrustedSiteWarning, warningMsg, 1, 0,
                1, 1, 1.0, 0.0, GridBagConstraints.NORTHWEST,
                GridBagConstraints.BOTH, 0, 0,
                DIFFERENT_COMPONENT_SPACE, VERT_WINDOW_INSET);

        GridBagUtil.constrain(notTrustedSiteWarning, oneSession, 1, 1,
                1, 1, 0.0, 0.0, GridBagConstraints.SOUTHWEST,
                GridBagConstraints.NONE, 0, 0, 0, VERT_WINDOW_INSET);

        GridBagUtil.constrain(notTrustedSiteWarning,
                Box.createVerticalGlue(), 1, 2, 2, 1, 1.0, 1.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, 0, 0);


        return notTrustedSiteWarning;
    }

    JButton accept;
    public void setVisible(boolean visible) {
        if (visible) {
            accept.grabFocus();
            setDefaultButton(accept);
        }
        super.setVisible(visible);
    }

    /**
      * create all the action buttons (Accept, Reject, View Certificate, and Help)
      */
    private JPanel createActionButtons() {
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridBagLayout());
        
        accept = JButtonFactory.create(
                                       _resource.getString("PromptForTrustDialog", "accept"),
                                       buttonActionListener, "ACCEPT");
        accept.setToolTipText(_resource.getString("PromptForTrustDialog", "accept_tt"));
        accept.registerKeyboardAction(buttonActionListener, "ACCEPT",
                                      KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0),
                                      JComponent.WHEN_IN_FOCUSED_WINDOW);
        
        JButton reject = JButtonFactory.create(
                                               _resource.getString("PromptForTrustDialog", "reject"),
                                               buttonActionListener, "REJECT");
        reject.setToolTipText(_resource.getString("PromptForTrustDialog", "reject_tt"));
        reject.registerKeyboardAction(buttonActionListener, "REJECT",
                                      KeyStroke.getKeyStroke(KeyEvent.VK_R, 0),
                                      JComponent.WHEN_IN_FOCUSED_WINDOW);
        
        JButton viewCert = JButtonFactory.create(
                                                 _resource.getString("PromptForTrustDialog",
                                                                     "viewCert"), buttonActionListener, "VIEWCERT");
        viewCert.registerKeyboardAction(buttonActionListener, "VIEWCERT",
                                        KeyStroke.getKeyStroke(KeyEvent.VK_V, 0),
                                        JComponent.WHEN_IN_FOCUSED_WINDOW);
        viewCert.setToolTipText(_resource.getString("PromptForTrustDialog", "viewCert_tt"));
        
        JButton help =
            JButtonFactory.createHelpButton(buttonActionListener);
        
        JButtonFactory.resizeGroup(accept, reject, help);

        int x = 0;
        GridBagUtil.constrain(buttonPanel, accept, x, 0, 1, 1, 0.0,
                              0.0, GridBagConstraints.NORTH,
                              GridBagConstraints.BOTH, DIFFERENT_COMPONENT_SPACE, 0,
                              0, COMPONENT_SPACE);

        GridBagUtil.constrain(buttonPanel, reject, ++x, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, DIFFERENT_COMPONENT_SPACE, 0,
                0, COMPONENT_SPACE);

        GridBagUtil.constrain(buttonPanel, viewCert, ++x, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, DIFFERENT_COMPONENT_SPACE, 0,
                0, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(buttonPanel, help, ++x, 0, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, DIFFERENT_COMPONENT_SPACE, 0,
                0, 0);

        return buttonPanel;
    }
}
