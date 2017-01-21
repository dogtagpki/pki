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

import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Vector;

import javax.swing.Box;
import javax.swing.ButtonGroup;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.border.TitledBorder;

import com.netscape.cmsutil.crypto.CryptoUtil;
import com.netscape.management.client.util.GridBagUtil;
import com.netscape.management.client.util.MultilineLabel;
import com.netscape.management.client.util.ResourceSet;
import com.netscape.management.client.util.UtilConsoleGlobals;
import com.netscape.management.nmclf.SuiConstants;
import com.netscape.management.nmclf.SuiOptionPane;

/**
 *
 * Prompt user to see which token they want to use, and weather or not
 * certificate has been installed or not.
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 */
class CertRequestSelectTokenPane extends JPanel implements SuiConstants,
IKeyCertPage {

    JComboBox tokenSelection = new JComboBox();
    JRadioButton _no;
    JRadioButton _yes;
    JRadioButton _noneed;

    String _defaultToken;
    String _internal;

    /**
     * Determain whether a cgi need to be call again
     */
    boolean modified = true;


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
        //might have to call cgi that loadmodule...
        observable.put("sie",
                KeyCertUtility.createTokenName(
                observable.getConsoleInfo()));

        if (tokenSelection.getItemCount() == 0) {
            observable.put("createTrust" , new Boolean(true));

            KeyCertTaskInfo taskInfo = observable.getTaskInfo();
            taskInfo.put("sie", observable.get("sie"));

            try {
                taskInfo.exec(taskInfo.SEC_LSTOKEN);
            } catch (Exception e) {
                SuiOptionPane.showMessageDialog(
                        UtilConsoleGlobals.getActivatedFrame(),
                        e.getMessage());
                return true;
            }

            Vector cipherList = taskInfo.getResponse().getFamilyList();
            for (int i = 0; i < cipherList.size(); i++) {
                CipherEntry cipher = (CipherEntry)(cipherList.elementAt(i));
                JComboBox tokenNames = cipher.getTokenComboBox();
                for (int j = 0; j < cipher.getTokenCount(); j++) {
                    tokenSelection.addItem(tokenNames.getItemAt(j));
                }
                if (tokenSelection.getItemCount() > 0) {
                    observable.put("createTrust" , new Boolean(false));
                }
            }


            boolean noDefaultToken = true;
            for (int i = tokenSelection.getItemCount() - 1; i >= 0; i--) {
                if (tokenSelection.getItemAt(i).equals(_defaultToken)) {
                    noDefaultToken = false;
                }
            }
            if (noDefaultToken) {
                tokenSelection.addItem(_defaultToken);
                observable.put("createTrust" , new Boolean(true));
            }

            try {
                tokenSelection.setSelectedIndex(0);
            } catch (Exception e) {}
        }

        return true;
    }


    /**
      * Checks if this panel can be hidden
      * @return true if this page can be hide
      */
    public boolean pageHide(WizardObservable observable) {
        /*observable.put("isInternal"   , ((TOGGLEPANEeditor)(questionPane.getCtrlByName("isInternal"))).getValue());*/

        try {
            observable.put("isInternal" , new Boolean(true));
            if (!(((String)(tokenSelection.getSelectedItem())).
                    toLowerCase()).startsWith(_internal.toLowerCase())) {
                observable.put("isInternal" , new Boolean(false));
            }
        } catch (Exception e) {}
        if (modified) {
            observable.put("CertReqModified", new Boolean(true));
            observable.put("tokenName" , tokenSelection.getSelectedItem());
            observable.put("requestCert" , new Boolean(_no.isSelected()));
            observable.put("installCert" ,
                    new Boolean(!(_noneed.isSelected())));
            observable.put("noneed" , new Boolean(_noneed.isSelected()));
            modified = false;
        }

        return true;
    }

    /**
      * Listen to changes to determain if cgi need to be called again
      *
      */
    class ModifiedActionListener implements ActionListener {
        public void actionPerformed(ActionEvent e) {
            modified = true;
        }
    }



    /**
      *
      * Convinent method for create a numbered component:
      * [panel]
      *    1. bla bla bla
      *    2. bla bla bla
      * [panel]
      *
      */
    private void addNumberedComponent(JPanel p, int count, Component c,
            Vector components) {
        //JPanel entry = new JPanel();
        //entry.setLayout(new GridBagLayout());
        GridBagUtil.constrain(p,
                Box.createRigidArea(
                new Dimension(SEPARATED_COMPONENT_SPACE, 0)), 0,
                count - 1, 1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, 0, 0);
        GridBagUtil.constrain(p,
                new JLabel(Integer.toString(count) + ".  "), 1,
                count - 1, 1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.NONE, 0, 0, 0, 0);
        GridBagUtil.constrain(p, c, 2, count - 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);


        for (int i = 0; i < components.size(); i++) {
            GridBagUtil.constrain(p,
                    (Component)(components.elementAt(i)), 2,
                    count + i, 1, 1, 1.0, 0.0,
                    GridBagConstraints.WEST, GridBagConstraints.NONE,
                    0, 0, 0, 0);
        }

        //p.add(entry);
    }

    /**
      *
      * Create a token selection panel for Key & Cert wizard.
      *
      */
    public CertRequestSelectTokenPane() {
        super();
        setLayout(new GridBagLayout());

        ResourceSet resource = KeyCertUtility.getKeyCertWizardResourceSet();

        _internal = resource.getString("SelectToken", CryptoUtil.INTERNAL_TOKEN_NAME);
        _defaultToken = resource.getString("SelectToken", "defaultToken");

        _no = new JRadioButton(resource.getString("SelectToken", "no"),
                true);
        _yes = new JRadioButton(resource.getString("SelectToken", "yes"),
                false);
        _noneed =
                new JRadioButton(resource.getString("SelectToken", "noNeed"),
                false);

        JLabel useExt_noneed =
                new JLabel(resource.getString("SelectToken", "noNeed_ext"));
        Insets b = _noneed.getMargin();
        useExt_noneed.setBorder( new EmptyBorder( new Insets(0,
                12 + b.right + _noneed.getHorizontalTextPosition(),
                b.bottom, b.right)));



        ModifiedActionListener listener = new ModifiedActionListener();
        _no.addActionListener(listener);
        _yes.addActionListener(listener);
        _noneed.addActionListener(listener);
        tokenSelection.addActionListener(listener);


        ButtonGroup buttonGroup = new ButtonGroup();
        buttonGroup.add(_no);
        buttonGroup.add(_yes);
        buttonGroup.add(_noneed);


        int y = 0;

        setBorder( new TitledBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)),
                resource.getString("SelectToken", "title")));


        JPanel tokenSelectPane = new JPanel();
        //tokenSelectPane.setLayout(new BoxLayout(tokenSelectPane, BoxLayout.Y_AXIS));
        tokenSelectPane.setLayout(new GridBagLayout());

        JLabel _pickToken =
                new JLabel(resource.getString("SelectToken", "pickToken"));
        Vector components = new Vector();
        components.addElement(tokenSelection);
        addNumberedComponent(tokenSelectPane, ++y, _pickToken, components);
        GridBagUtil.constrain(this, tokenSelectPane, 0, y, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);


        JPanel certInstPane = new JPanel();
        //certInstPane.setLayout(new BoxLayout(certInstPane, BoxLayout.Y_AXIS));
        certInstPane.setLayout(new GridBagLayout());

        components = new Vector();
        components.addElement(_no);
        components.addElement(_yes);
        //need a radio button that can wrap the string.
        components.addElement(_noneed);
        components.addElement(useExt_noneed);
        addNumberedComponent(certInstPane, ++y,
                new MultilineLabel(
                resource.getString("SelectToken", "certReadyForInst")),
                components);
        GridBagUtil.constrain(this, certInstPane, 0, y, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, DIFFERENT_COMPONENT_SPACE, 0);

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
     CertRequestSelectTokenPane c = new CertRequestSelectTokenPane();
     f.getContentPane().add("North",c );
     f.setSize(400,400);
     f.show();
     }*/

}
