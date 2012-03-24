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

class CertDetailInfoDialog extends AbstractDialog implements SuiConstants {


    JLabel serialNumber = new JLabel();
    JLabel valid = new JLabel();
    JLabel fingerprint = new JLabel();
    JLabel trust = new JLabel();
    JPanel mainPane = new JPanel();

    ResourceSet resource = new ResourceSet("com.netscape.admin.certsrv.security.CertManagementResource");

    void setCertInfo(CertInfo certInfo) {

        serialNumber.setText(certInfo.getSerialNumber());
        valid.setText( KeyCertUtility.replace( KeyCertUtility.replace(
                resource.getString("CertDetailInfoDialog",
                "validFromTo"), "%FROM", certInfo.getValidFrom()), "%TO",
                certInfo.getValidTo()));
        fingerprint.setText(certInfo.getFingerPrint());
        trust.setText(certInfo.trusted() ?
                resource.getString("CertDetailInfoDialog", "trustString") :
                resource.getString("CertDetailInfoDialog", "notTrustString"));

        mainPane.doLayout();
        mainPane.repaint();

        pack();
    }

    public CertDetailInfoDialog(JFrame parent, CertInfo certInfo) {
        super(parent, "", true, CLOSE);

        setTitle(resource.getString("CertDetailInfoDialog", "title"));

        mainPane.setLayout(new GridBagLayout());
        mainPane.setBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)));

        int y = 0;
        GridBagUtil.constrain(mainPane,
                new JLabel( resource.getString("CertDetailInfoDialog",
                "serialNumberLabel")), 0, y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(mainPane, serialNumber, 0, ++y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, DIFFERENT_COMPONENT_SPACE,
                COMPONENT_SPACE, 0);

        GridBagUtil.constrain(mainPane, valid, 0, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(mainPane,
                new JLabel( resource.getString("CertDetailInfoDialog",
                "fingerprintLabel")), 0, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(mainPane, fingerprint, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, DIFFERENT_COMPONENT_SPACE,
                COMPONENT_SPACE, 0);

        GridBagUtil.constrain(mainPane, trust, 0, ++y, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        getContentPane().add(mainPane);

        setCertInfo(certInfo);

        pack();
        setMinimumSize(getSize());
        setResizable(false);
    }
}

