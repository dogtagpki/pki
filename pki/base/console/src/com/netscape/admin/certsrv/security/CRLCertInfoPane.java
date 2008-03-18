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

class CRLCertInfoPane extends JPanel implements SuiConstants {


    JLabel _certName;
    MultilineLabel _issuer;
    //MultilineLabel _subject;
    MultilineLabel _valid;
    ResourceSet _resource;

    public void setCertInfo(CertInfo certInfo) {
        _certName.setText(certInfo.getCertName());
        _issuer.setText(certInfo.getIssuer());
        //_subject.setText(certInfo.getSubject());
        _valid.setText( KeyCertUtility.replace( KeyCertUtility.replace(
                _resource.getString("CRLDetailInfoDialog",
                "validFromTo"), "%FROM", certInfo.getValidFrom()), "%TO",
                certInfo.getValidTo()));

    }

    public CRLCertInfoPane(ResourceSet resource) {
        setLayout(new GridBagLayout());

        _resource = resource;

        _certName = new JLabel();
        _issuer = new MultilineLabel();
        //_subject  = new MultilineLabel();
        _valid = new MultilineLabel();


        setBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)));



        GridBagUtil.constrain(this,
                new JLabel(
                _resource.getString("CRLInfoDialog", "issuer")), 0, 0,
                1, 1, 1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0, COMPONENT_SPACE, 0);

        JScrollPane issuerScrollPane = new JScrollPane(_issuer,
                JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED,
                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        issuerScrollPane.setBorder(
                new CompoundBorder(UITools.createLoweredBorder(),
                new EmptyBorder(VERT_COMPONENT_INSET,
                HORIZ_COMPONENT_INSET, VERT_COMPONENT_INSET,
                HORIZ_COMPONENT_INSET)));
        GridBagUtil.constrain(this, issuerScrollPane, 0, 1, 1, 1, 1.0,
                1.0, GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, _valid, 0, 2, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0, 0, 0);

        GridBagUtil.constrain(this, Box.createGlue(), 0, 3, 1, 1, 1.0,
                1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);
    }

    public CRLCertInfoPane(CertInfo certInfo, ResourceSet resource) {
        this(resource);

        setCertInfo(certInfo);
    }


    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     f.setSize(400,400);
     f.getContentPane().add(new CRLCertInfoPane(new CertInfo("Buddha", "Netscape", "Netscape", null, null, "Jan 1, 1998", "Jan 1, 2000", null, null, null, null), new ResourceSet("com.netscape.admin.certsrv.security.CertManagementResource")));
     f.show();

     }*/
}
