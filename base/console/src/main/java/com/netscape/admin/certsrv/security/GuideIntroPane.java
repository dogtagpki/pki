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
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

class GuideIntroPane extends JPanel implements SuiConstants, IKeyCertPage {

    public JPanel getPanel() {
        return this;
    }

    public boolean pageShow(WizardObservable observable) {
        return true;
    }

    public boolean pageHide(WizardObservable observable) {
        return true;
    }

    private void addNumberedComponent(JPanel p, int count, Component c) {
        //JPanel entry = new JPanel();
        //entry.setLayout(new GridBagLayout());

        GridBagUtil.constrain(p,
                Box.createRigidArea(
                new Dimension(SEPARATED_COMPONENT_SPACE, 0)), 0,
                count - 1, 1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.NONE, 0, 0, 0, 0);
        GridBagUtil.constrain(p,
                new JLabel(Integer.toString(count) + ".  "), 1,
                count - 1, 1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.NONE, 0, 0, 0, 0);
        GridBagUtil.constrain(p, c, 2, count - 1, 1, 1, 1.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);
        //p.add(entry);
    }


    public GuideIntroPane() {
        super();
        setLayout(new GridBagLayout());

        int y = 0;


        ResourceSet resource = KeyCertUtility.getKeyCertWizardResourceSet();


        setBorder( new TitledBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)),
                resource.getString("GuideIntroPane", "title")));

        GridBagUtil.constrain(this,
                new MultilineLabel(
                resource.getString("GuideIntroPane", "explain")), 0,
                ++y, 1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0,
                SEPARATED_COMPONENT_SPACE, 0);

        JPanel p = new JPanel();
        //p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setLayout(new GridBagLayout());
        int count = 0;

        MultilineLabel _step1 = new MultilineLabel(
                resource.getString("GuideIntroPane", "step1"));
        MultilineLabel _step2 = new MultilineLabel(
                resource.getString("GuideIntroPane", "step2"));
        MultilineLabel _step3 = new MultilineLabel(
                resource.getString("GuideIntroPane", "step3"));
        addNumberedComponent(p, ++count, _step1);
        addNumberedComponent(p, ++count, _step2);
        addNumberedComponent(p, ++count, _step3);
        GridBagUtil.constrain(this, p, 0, ++y, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, Box.createVerticalGlue(), 0, ++y,
                1, 1, 1.0, 1.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);

        GridBagUtil.constrain(this,
                new JLabel(
                resource.getString(null, "clickNextToContinue")), 0,
                ++y, 1, 1, 1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);
    }

    /*public static void main(String arg[]) {
     JFrame f = new JFrame();
     f.getContentPane().add(new GuideIntroPane());
     //f.getContentPane().add(new MultilineLabel("adsf;klj a;sldkj ;alskj ;alsj f;alsdjf ;lakjfd ;asdjf ;aldsjf "));
     f.setSize(400,400);
     f.show();
     }*/

}
