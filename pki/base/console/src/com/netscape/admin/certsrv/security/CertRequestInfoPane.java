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
import javax.swing.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;

class CertRequestInfoPane extends JPanel implements SuiConstants,
IKeyCertPage {

    boolean modified = false;

    JTextField name = new JTextField();
    JTextField phone = new JTextField();
    SingleByteTextField dn = new SingleByteTextField();
    SingleByteTextField email = new SingleByteTextField();
    JTextField o = new JTextField();
    JTextField ou = new JTextField();
    JTextField l = new JTextField();
    JComboBox st;
    JComboBox c;


    JLabel _nameLabel;
    JLabel _phoneLabel;
    JLabel _dnLabel;
    JLabel _emailLabel;
    JLabel _oLabel;
    JLabel _ouLabel;
    JLabel _lLabel;
    JLabel _stLabel;
    JLabel _cLabel;
    JLabel _requiredLabel;

    JLabel _dnExample;

    IWizardControl control;

    ResourceSet resource;

    JPanel statePanel = new JPanel();

    public JPanel getPanel() {
        return this;
    }

    public boolean pageShow(WizardObservable observable) {
        boolean show =
                ((Boolean)(observable.get("requestCert"))).booleanValue();

        if (show) {
            control = (IWizardControl)(observable.get("Wizard"));
            setEnableNextButton();
        }
        return show;
    }

    public boolean pageHide(WizardObservable observable) {

        KeyCertTaskInfo taskInfo = observable.getTaskInfo();

        if (modified) {
            observable.put("CertReqModified", new Boolean(true));

            Hashtable param = (Hashtable)(observable.get("CertReqCGIParam"));
            param.put("requestor_name", name.getText());
            param.put("telephone" , phone.getText());
            param.put("common_name" , dn.getText());
            param.put("email_address" , email.getText());
            param.put("organization" , o.getText());
            param.put("org_unit" , ou.getText());
            param.put("locality" , l.getText());
            param.put("state" ,
                    st.getSelectedItem() == null ? "":
                    st.getSelectedItem());
            param.put("country" ,
                    ((String)(c.getSelectedItem())).substring(0, 2));
            param.put("tokenName" , observable.get("tokenName"));
        }

        return true;
    }

    void setEnableNextButton() {
        if ((name.getText().length() == 0) ||
                (dn.getText().length() == 0) ||
                (phone.getText().length() == 0) ||
                (email.getText().length() == 0) ||
                (o.getText().length() == 0) ||
                (((String)(c.getSelectedItem())).length() < 2) ||
                (dn.getText().indexOf(".") == -1)) {
            control.setCanGoForward(false);
        } else {
            control.setCanGoForward(true);
        }
    }

    class InfoPaneActionListener implements ActionListener, KeyListener, FocusListener{
        public void actionPerformed(ActionEvent e) {
            modified = true;
            setEnableNextButton();

            if (e.getSource() == c) {
                setupState(c.getSelectedItem().toString());
            }
        }
        public void keyTyped(KeyEvent e) {}
        public void keyPressed(KeyEvent e) {}
        public void keyReleased(KeyEvent e) {
            modified = true;
            setEnableNextButton();

            if (e.getSource() == c) {
                setupState(c.getSelectedItem().toString());
            }
        }

        public void focusGained(FocusEvent e) {}
        public void focusLost(FocusEvent e) {
            if (!(e.isTemporary()) && (e.getComponent() == dn) &&
                (dn.getText().indexOf(".") == -1)) {
                JOptionPane.showMessageDialog(
                    UtilConsoleGlobals.getActivatedFrame(),
                    resource.getString("CertRequestInfoPane", "invalidFQDN"),
                    resource.getString("CertRequestInfoPane",
                                       "invalidFQDNDialogTitle"),
                    JOptionPane.ERROR_MESSAGE);
                control.setCanGoForward(false);
            }
        }
    }

    private JLabel rightAlignLabel(String label) {
        return new JLabel(label, JLabel.RIGHT);
    }

    private JPanel getInfoPane() {
        JPanel infoPane = new JPanel();
        infoPane.setLayout(new GridBagLayout());

        InfoPaneActionListener listener = new InfoPaneActionListener();
        name.addActionListener(listener);
        phone.addActionListener(listener);
        dn.addActionListener(listener);
        email.addActionListener(listener);
        o.addActionListener(listener);
        ou.addActionListener(listener);
        l.addActionListener(listener);
        st.addActionListener(listener);
        c.addActionListener(listener);

        name.addKeyListener(listener);
        phone.addKeyListener(listener);
        dn.addKeyListener(listener);
        email.addKeyListener(listener);
        o.addKeyListener(listener);
        ou.addKeyListener(listener);
        l.addKeyListener(listener);
        st.addKeyListener(listener);
        c.addKeyListener(listener);

        dn.addFocusListener(listener);

        st.setEditable(true);
        c.setEditable(true);



        int y = 0;

        GridBagUtil.constrain(infoPane, _nameLabel, 0, y, 1, 1, 1.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(infoPane, name, 1, y, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(infoPane, _phoneLabel, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(infoPane, phone, 1, y, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(infoPane, _dnLabel, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                0, 0, 0, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(infoPane, dn, 1, y, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        GridBagUtil.constrain(infoPane, _dnExample, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.EAST, GridBagConstraints.BOTH,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(infoPane, _emailLabel, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(infoPane, email, 1, y, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(infoPane, _oLabel, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(infoPane, o, 1, y, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(infoPane, _ouLabel, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(infoPane, ou, 1, y, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(infoPane, _lLabel, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(infoPane, l, 1, y, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(infoPane, _stLabel, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);


        GridBagUtil.constrain(infoPane, statePanel/*st*/, 1, y, 1, 1,
                0.0, 0.0, GridBagConstraints.EAST,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(infoPane, _cLabel, 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.WEST, GridBagConstraints.BOTH,
                0, 0, COMPONENT_SPACE, DIFFERENT_COMPONENT_SPACE);

        GridBagUtil.constrain(infoPane, c, 1, y, 1, 1, 0.0, 0.0,
                GridBagConstraints.EAST, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        GridBagUtil.constrain(infoPane, _requiredLabel, 1, ++y, 1, 1,
                1.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE,
                DIFFERENT_COMPONENT_SPACE);


        return infoPane;
    }

    private void setupState(String country) {
        String stList;
        statePanel.remove(st);
        try {
            stList = resource.getString("CertRequestInfoPane",
                    "state-"+country.substring(0, 2).toUpperCase());
            if (stList != null && !(stList.equals(""))) {

                StringTokenizer stateTokens =
                        new StringTokenizer(stList, ",", false);
                Vector states = new Vector();
                while (stateTokens.hasMoreTokens()) {
                    states.addElement(stateTokens.nextToken());
                }
                //this will make it load faster.
                //It will do some extra work if we call addItem() one at a time

                st = new JComboBox(states);
            }
            else {
                st.removeAllItems();
            }
        }
        catch (Exception e) {
            st.removeAllItems();
        }

        GridBagUtil.constrain(statePanel, st, 0, 0, 1, 1, 1.0, 1.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, 0, 0);

        statePanel.validate();
        statePanel.repaint();

        try {
            st.setSelectedItem( resource.getString("CertRequestInfoPane",
                    "defaultState-"+
                    country.substring(0, 1).toUpperCase()));
        } catch (Exception e) {}

    }

    public CertRequestInfoPane() {
        super();
        setLayout(new GridBagLayout());
        statePanel.setLayout(new GridBagLayout());

        resource = KeyCertUtility.getKeyCertWizardResourceSet();

        _nameLabel = rightAlignLabel(
                resource.getString("CertRequestInfoPane", "nameLabel"));
        _phoneLabel = rightAlignLabel(
                resource.getString("CertRequestInfoPane", "phoneLabel"));
        _dnLabel = rightAlignLabel(
                resource.getString("CertRequestInfoPane", "dnLabel"));
        _emailLabel = rightAlignLabel(
                resource.getString("CertRequestInfoPane", "emailLabel"));
        _oLabel = rightAlignLabel(
                resource.getString("CertRequestInfoPane", "oLabel"));
        _ouLabel = rightAlignLabel(
                resource.getString("CertRequestInfoPane", "ouLabel"));
        _lLabel = rightAlignLabel(
                resource.getString("CertRequestInfoPane", "lLabel"));
        _stLabel = rightAlignLabel(
                resource.getString("CertRequestInfoPane", "stLabel"));
        _cLabel = rightAlignLabel(
                resource.getString("CertRequestInfoPane", "cLabel"));


        _dnExample = rightAlignLabel(
                resource.getString("CertRequestInfoPane", "dnExample"));

        _requiredLabel =
                new JLabel(resource.getString("CertRequestInfoPane", "requiredLabel"));


        String cList = resource.getString("CertRequestInfoPane", "country");
        StringTokenizer countryTokens =
                new StringTokenizer(cList, ",", false);
        Vector countries = new Vector();
        while (countryTokens.hasMoreTokens()) {
            countries.addElement(countryTokens.nextToken());
        }

        st = new JComboBox();
        c = new JComboBox(countries);

        try {
            c.setSelectedItem(
                    resource.getString("CertRequestInfoPane", "defaultCountry"));
        } catch (Exception e) {}

        setupState(c.getSelectedItem().toString());


        setBorder( new TitledBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)),
                resource.getString("CertRequestInfoPane", "title")));

        int y = 0;

        GridBagUtil.constrain(this, getInfoPane(), 0, ++y, 1, 1, 1.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

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
     f.getContentPane().add("North", new CertRequestInfoPane());
     f.setSize(400,400);
     //f.pack();
     f.show();
     }*/

}
