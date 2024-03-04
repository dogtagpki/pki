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

import com.netscape.management.client.components.*;
import java.awt.*;
import java.awt.event.*;
import java.text.MessageFormat;
import java.util.*;
import javax.swing.*;
import com.netscape.management.client.util.*;
import com.netscape.management.client.components.ErrorDialog;
import com.netscape.management.nmclf.*;
import netscape.ldap.util.DN;

class CertInstallCertInfoPage extends WizardPage implements SuiConstants {

    MultilineLabel _thisCertLabel;
    Hashtable _newCert = null;

    void showSameSubjectInfoDialog(Hashtable cert) {
        
        String nickname = (String)cert.get("NICKNAME");
        Hashtable subject = (Hashtable)(cert.get("SUBJECT"));
        String subjectDN = (String)cert.get("SUBJECT_DN");
        
        JDialog parent = (JDialog)SwingUtilities.getAncestorOfClass(JDialog.class, this);
        
        ResourceSet resource = KeyCertUtility.getResourceSet();
		String title = resource.getString("CertInstallCertInfoPage", "sameSubjectTitle");
		String msg   = resource.getString("CertInstallCertInfoPage", "sameSubjectMessage");
		String rawDetail = resource.getString("CertInstallCertInfoPage", "sameSubjectDetail");
        String detail = MessageFormat.format(rawDetail, new Object[] { nickname, subjectDN });
		final ErrorDialog infoDialog =
            new ErrorDialog(parent, title, msg, null, detail,
			                ErrorDialog.OK, ErrorDialog.OK);
        infoDialog.hideDetail();
        infoDialog.setIcon(ErrorDialog.INFORMATION_ICON);
        
        // Delay the dialog display so it shows up over the CertName page
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                infoDialog.show();
            }
        });                                          
    }

    Hashtable getCertBySubject(String checkSubject) { 
        Vector installedServerCerts = (Vector)(getDataModel().getValue("installedServerCerts"));
        if (Debug.isEnabled()) {
            Debug.println("getCertBySubject: installedCertList=" + installedServerCerts);
        }
        for (int i=0; installedServerCerts != null && i < installedServerCerts.size(); i++) {
            Hashtable cert = (Hashtable)installedServerCerts.elementAt(i);
            String subject = (String)cert.get("SUBJECT_DN");
            if (subject != null) {
                DN dn1 = new DN(subject), dn2 = new DN(checkSubject);
                if (dn1.equals(dn2)) {
                    return cert;
                }
            }
        }
        return null;
    }

    public boolean nextInvoked() {
        
        String val = (String)getDataModel().getValue("certtype");
        int certType = (val == null) ? -1 : Integer.parseInt(val);

        if (_newCert != null && certType == CertInstallWizard.SERVER) {
            String certSubject = (String)_newCert.get("SUBJECT_DN");
            if (certSubject != null) {
                Hashtable existingCert = getCertBySubject(certSubject);
                if (existingCert != null) {
                    IDataCollectionModel dataModel = getDataModel();
                    dataModel.setValue("certname", existingCert.get("NICKNAME"));
                    showSameSubjectInfoDialog(existingCert);
                }
            }
        }
        return true;
    }
        
    public void pageShown() {
        removeAll();

        CertificateList certList = (CertificateList)(getDataModel().getValue("certlist"));

        if (certList.getCACerts().size()!=0) {
            _newCert = (Hashtable)(certList.getCACerts().elementAt(0));
        } else if (certList.getServerCerts().size() != 0) {
            _newCert = (Hashtable)(certList.getServerCerts().elementAt(0));
        } else {
            //no cert;
            return;
        }

        CertificateInfoPanels certInfo = new CertificateInfoPanels(_newCert);

        GridBagUtil.constrain(this, certInfo.getGeneralInfo(),
                              0, 0, 1, 1,
                              1.0, 1.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                              0, 0, DIFFERENT_COMPONENT_SPACE, 0);

        JButton showDetail = JButtonFactory.create("Details");
        showDetail.setToolTipText(KeyCertUtility.getResourceSet().getString("CertInstallCertInfoPage", "detail_tt"));
        showDetail.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                CertificateDetailDialog detailDialog = new CertificateDetailDialog(null, _newCert);
            }
        });

        GridBagUtil.constrain(this, showDetail,
                              0, 1, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.EAST, GridBagConstraints.NONE,
                              0, 0, 0, 0);
    }

    public void helpInvoked() {
        KeyCertUtility.getHelp().contextHelp("CertInstallCertInfoPage", "help");
    }

    public CertInstallCertInfoPage() {
        super(KeyCertUtility.getResourceSet().getString("CertInstallCertInfoPage", "pageTitle"));
        setLayout(new GridBagLayout());

        ResourceSet resource = KeyCertUtility.getResourceSet();

        _thisCertLabel = new MultilineLabel(resource.getString("CertInstallCertInfoPage", "thisCertLabel"));

        m_canMoveForward = true;
    }
}
