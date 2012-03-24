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
 * Step 2 of the certificate request under Key & Cert wizard.
 * Pompt user to enter which type of certificate they want to request
 * and the email address of the CA the request will be sent to.
 *
 * @version    1.0    98/07/10
 * @author     <A HREF="mailto:shihcm@netscape.com">shihcm@netscape.com</A>
 *
 */
class CertRequestTypePane extends JPanel implements SuiConstants,
IKeyCertPage {

    JRadioButton _email;
    SingleByteTextField _emailAddr = new SingleByteTextField();
    JRadioButton _url;
    SingleByteTextField _urlAddr = new SingleByteTextField();

    JLabel _caEmailAddr;

    JRadioButton _new;
    JRadioButton _renew;

    /**
     * Get the panel that is going to be displayed
     * @return a panel to be displayed by the key & cert wizard
     */
    IWizardControl control;
    JButton _caButton;

    MultilineLabel _showCALabel;

    /**
     * Determain whether a cgi need to be call again to decode
     */
    boolean modified = false;

    public static Hashtable param = new Hashtable();

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

        boolean show =
                ((Boolean)(observable.get("requestCert"))).booleanValue();

        if (show) {
            control = (IWizardControl)(observable.get("Wizard"));
            setEnableNextButton();
        }

        if (observable.get("CertReqCGIParam") == null) {
            observable.put("CertReqCGIParam", param);
        }

        return show;
    }


    /**
      * Checks if this panel can be hidden
      * @return true if this page can be hide
      */
    public boolean pageHide(WizardObservable observable) {
        KeyCertTaskInfo taskInfo = observable.getTaskInfo();

        //see if this page has been modified.
        if (modified) {
            observable.put("CertReqModified", new Boolean(true));

            //radio button in a group will called twice one for the component that is loosing the focus
            //and one for the component that is getting the focus
            param.put("cert_type" , _new.isSelected() ? "0":"1");

            //remove url support
            param.put("xmt_select" , _email.isSelected() ? "0":"1");
            param.put("url" , _urlAddr.getText());
            param.put("cert_auth" , _emailAddr.getText());

            //support only e-mail at this moment
            //param.put("xmt_select" , "0");
            //param.put("cert_auth"  , _emailAddr.getText());

            modified = false;
        }

        return true;
    }


    /**
      * Listen to changes (key strokes or change in text area or text field)
      * then determain (call setEnableNextButton()) if wizard can proceed
      */
    class TypeActionListener implements KeyListener, ActionListener {
        public void keyTyped(KeyEvent e) {}
        public void keyPressed(KeyEvent e) {}
        public void keyReleased(KeyEvent e) {
            setEnableNextButton();
            modified = true;
        }
        public void actionPerformed(ActionEvent e) {

            if (e.getActionCommand().equals("SHOWCA")) {
                Browser browser = new Browser();
                browser.open("https://certs.netscape.com/server.html",
                        browser.NEW_WINDOW);
            } else {
                if (_email.isSelected()) {
                    _urlAddr.setEnabled(false);
                    _emailAddr.setEnabled(true);
                } else {
                    _urlAddr.setEnabled(true);
                    _emailAddr.setEnabled(false);
                }
                setEnableNextButton();
                modified = true;
            }
        }
    }

    /**
      * Detarmain all the require field has been fill in, if true the
      * enable the "Next >" button.
      */
    void setEnableNextButton() {
        if ((_email.isSelected() && (_emailAddr.getText().length() > 0)) ||
                (_url.isSelected() && (_urlAddr.getText().length() > 0))) {
            control.setCanGoForward(true);
        } else {
            control.setCanGoForward(false);
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
                new Dimension(DIFFERENT_COMPONENT_SPACE, 0)), 0,
                count - 1, 1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.NONE, 0, 0, 0, 0);

        GridBagUtil.constrain(p,
                new JLabel(Integer.toString(count) + ".  "), 1,
                count - 1, 1, 1, 0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.NONE, 0, 0, 0, 0);

        GridBagUtil.constrain(p, c, 2, count - 1, 1, 1, 0.0, 0.0,
                GridBagConstraints.NORTH, GridBagConstraints.BOTH, 0,
                0, COMPONENT_SPACE, 0);

        for (int i = 0; i < components.size(); i++) {
            GridBagUtil.constrain(p,
                    (Component)(components.elementAt(i)), 2,
                    count + i, 1, 1, 1.0, 0.0,
                    GridBagConstraints.NORTH, GridBagConstraints.BOTH,
                    0, 0, 0, 0);
        }

        //p.add(entry);
    }



    TypeActionListener listener = new TypeActionListener();


    /**
     * Prompt user to enter e-mail address of the CA where the
     * cert request will submit.
     *
     * Comment out submit by url, will not support in 4.0 but will
     * after 4.1 with agree upon standard between kingpin and cert
     * server.
     *
     */
    private JPanel getRequestViaPane() {
        JPanel requestViaPane = new JPanel();
        requestViaPane.setLayout(new GridBagLayout());

        ButtonGroup buttonTypeGroup = new ButtonGroup();
        buttonTypeGroup.add(_new);
        buttonTypeGroup.add(_renew);

        ButtonGroup buttonViaGroup = new ButtonGroup();
        buttonViaGroup.add(_email);
        buttonViaGroup.add(_url);

        int y = 0;

        _email.addActionListener(listener);
        GridBagUtil.constrain(requestViaPane, _email, 0, y, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        /*GridBagUtil.constrain(requestViaPane, _caEmailAddr,
                              0, y, 1, 1,
                              0.0, 0.0,
                              GridBagConstraints.NORTH, GridBagConstraints.BOTH,
         0, 0, COMPONENT_SPACE, 0);*/

        _emailAddr.addKeyListener(listener);
        GridBagUtil.constrain(requestViaPane, _emailAddr, 1, y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0,
                DIFFERENT_COMPONENT_SPACE, COMPONENT_SPACE, 0);

        _url.addActionListener(listener);
        GridBagUtil.constrain(requestViaPane, _url, 0, ++y, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        _urlAddr.addKeyListener(listener);
        GridBagUtil.constrain(requestViaPane, _urlAddr, 1, y, 1, 1,
                1.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.HORIZONTAL, 0,
                DIFFERENT_COMPONENT_SPACE, COMPONENT_SPACE, 0);
        _urlAddr.setEnabled(false);

        return requestViaPane;
    }



    /**
      *
      * return a panel contain a button which if clicked will lunch browser
      * and connect to netscape's cert server site.
      * The site contain links and information regarding CAs and certificate.
      *
      */
    private JPanel getCAButtonPane() {
        JPanel caButtonPane = new JPanel();
        caButtonPane.setLayout(new GridBagLayout());

        GridBagUtil.constrain(caButtonPane, _showCALabel, 0, 0, 1, 1,
                1.0, 0.0, GridBagConstraints.WEST,
                GridBagConstraints.BOTH, 0, 0, COMPONENT_SPACE, 0);

        _caButton.addActionListener(listener);
        _caButton.setActionCommand("SHOWCA");
        GridBagUtil.constrain(caButtonPane, _caButton, 1, 0, 1, 1, 1.0,
                0.0, GridBagConstraints.EAST, GridBagConstraints.NONE,
                0, DIFFERENT_COMPONENT_SPACE, COMPONENT_SPACE, 0);

        return caButtonPane;
    }

    /**
      *
      * Create a certificate request type selection pane for key & cert wizard
      *
      *
      */
    public CertRequestTypePane() {
        super();
        setLayout(new GridBagLayout());

        ResourceSet resource = KeyCertUtility.getKeyCertWizardResourceSet();

        _caButton = JButtonFactory.create(
                resource.getString("CertRequestTypePane", "showCAButtonLabel"));
        _email = new JRadioButton( resource.getString("CertRequestTypePane",
                "emailLabel"), true);
        _url = new JRadioButton(
                resource.getString("CertRequestTypePane", "urlLabel"),
                false);
        _new = new JRadioButton( resource.getString("CertRequestTypePane",
                "newcertLabel"), true);
        _renew = new JRadioButton( resource.getString("CertRequestTypePane",
                "renewcertLabel"), false);

        _caEmailAddr =
                new JLabel(resource.getString("CertRequestTypePane", "caEmailLabel"));

        _showCALabel = new MultilineLabel(
                resource.getString("CertRequestTypePane", "showCALabel"));

        setBorder( new TitledBorder( new CompoundBorder(new EtchedBorder(),
                new EmptyBorder(COMPONENT_SPACE, COMPONENT_SPACE,
                COMPONENT_SPACE, COMPONENT_SPACE)),
                resource.getString("CertRequestTypePane", "title")));

        int y = 0;

        JPanel requestTypePane = new JPanel();
        //requestTypePane.setLayout(new BoxLayout(requestTypePane, BoxLayout.Y_AXIS));
        requestTypePane.setLayout(new GridBagLayout());
        Vector components = new Vector();
        _new.addActionListener(listener);
        _renew.addActionListener(listener);
        components.addElement(_new);
        components.addElement(_renew);
        addNumberedComponent(requestTypePane, ++y,
                new MultilineLabel(
                resource.getString("CertRequestTypePane",
                "requestType")), components);
        GridBagUtil.constrain(this, requestTypePane, 0, y, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        JPanel requestViaPane = new JPanel();
        //requestViaPane.setLayout(new BoxLayout(requestViaPane, BoxLayout.Y_AXIS));
        requestViaPane.setLayout(new GridBagLayout());
        components = new Vector();
        components.addElement(getRequestViaPane());
        addNumberedComponent(requestViaPane, ++y,
                new MultilineLabel(
                resource.getString("CertRequestTypePane",
                "requestVia")), components);
        //addNumberedComponent(requestViaPane, ++y, new MultilineLabel(resource.getString("CertRequestTypePane", "requestViaEmail")), components);
        GridBagUtil.constrain(this, requestViaPane, 0, y, 1, 1, 0.0,
                0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

        GridBagUtil.constrain(this, getCAButtonPane(), 0, ++y, 1, 1,
                0.0, 0.0, GridBagConstraints.NORTH,
                GridBagConstraints.BOTH, 0, 0,
                DIFFERENT_COMPONENT_SPACE, 0);

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
     f.getContentPane().add("North", new CertRequestTypePane());
     f.setSize(400,400);
     f.show();
     }*/

}
