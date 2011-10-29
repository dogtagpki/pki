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

import java.util.*;
import javax.swing.*;
import java.awt.event.*;
import com.netscape.management.client.util.*;

class CipherEntry {
    private JCheckBox _cipherEnable;
    private JComboBox _tokenList;
    private JComboBox _certList;


    ResourceSet resource = new ResourceSet("com.netscape.admin.certsrv.security.EncryptionPaneResource");

    private Hashtable _tokenCertList;
    public CipherEntry(String cipherName, Hashtable tokenCertList) {
        _cipherEnable = new JCheckBox(cipherName);

        Vector tokenList = new Vector();
        Enumeration tokens = tokenCertList.keys();
        while (tokens.hasMoreElements()) {
            tokenList.addElement(tokens.nextElement());
        }

        if (tokenList.size() == 0) {
            tokenList.addElement(resource.getString("CipherEntry", "noToken"));
        }

        _tokenList = new JComboBox(tokenList);
        _tokenCertList = tokenCertList;
        _tokenList.addItemListener(new TokenListListener());

        _certList = new JComboBox();

        try {
            _tokenList.setSelectedIndex(0);
        } catch (Exception e) {}

    }


    public int getTokenCount() {
        return _tokenCertList.size();
    }

    class TokenListListener implements ItemListener {
        public void itemStateChanged(ItemEvent e) {
            if (e.getStateChange() == e.SELECTED) {
                //code here to swap in/out cert list
                _certList.removeAllItems();
                _certList.setEditable(false);
                if (_tokenCertList.get(e.getItem()) != null) {
                    Vector certList =
                            (Vector)(_tokenCertList.get(e.getItem()));
                    if (certList.size() != 0) {
                        if (((String)(certList.elementAt(0))).
                                toLowerCase().indexOf("unknown") != -1) {
                            _certList.addItem(
                                    resource.getString("CipherEntry", "enterCert"));
                            _certList.setEditable(true);
                        } else {
                            for (int i = 0; i < certList.size(); i++) {
                                _certList.addItem(certList.elementAt(i));
                            }
                        }
                    } else {
                        _certList.addItem(
                                resource.getString("CipherEntry", "noCert"));
                    }
                } else {
                    _certList.addItem(
                            resource.getString("CipherEntry", "noCert"));
                }
                try {
                    _certList.setSelectedIndex(0);
                    _certList.validate();
                    _certList.repaint();
                } catch (Exception exception) {}
            }
        }
    }

    public JCheckBox getCipherCheckBox() {
        return _cipherEnable;
    }
    public JComboBox getTokenComboBox() {
        return _tokenList;
    }
    public JComboBox getCertComboBox() {
        return _certList;
    }
    public String getCipherName() {
        return _cipherEnable.getText();
    }

    public String getSelectedToken() {
        String selected = (String)(_tokenList.getSelectedItem());
        if (selected.equalsIgnoreCase(
                resource.getString("CipherEntry", "noToken"))) {
            selected = "";
        }
        return selected;
    }

    public String getSelectedCertName() {
        String selected = (String)(_certList.getSelectedItem());
        if (selected == null || selected.equalsIgnoreCase(
                resource.getString("CipherEntry", "noCert")) ||
                selected.equalsIgnoreCase(
                resource.getString("CipherEntry", "enterCert"))) {
            selected = "";
        }

        return selected;
    }

    public boolean isEnabled() {
        return _cipherEnable.isSelected();
    }

    public void setSelectedToken(String token) {
        _tokenList.setSelectedItem(token);
    }

    public void setSelectedCert(String cert) {
        //if (_certList.getModel().contains(java.lang.Object elem) ) {
        _certList.setSelectedItem(cert);
        //}
    }

    public void setSelected(boolean enabled) {
        _cipherEnable.setSelected(enabled);
    }

    public void setEnabledAll(boolean enabled) {
        _cipherEnable.setEnabled(enabled);
        _tokenList.setEnabled(enabled);
        _certList.setEnabled(enabled);
    }


    /*public static void main(String arg[]) {
     JFrame f = new JFrame();

     Hashtable h = new Hashtable();
     Vector v1 = new Vector();
     Vector v2 = new Vector();
     v1.addElement("v1.1");
     v1.addElement("v1.2");
     v1.addElement("v1.3");
     v1.addElement("v1.4");
     v2.addElement("v2.1");
     v2.addElement("v2.2");
     v2.addElement("v2.3");
     v2.addElement("v2.4");
     h.put("v1", v1);
     h.put("v2", v2);

     CipherEntry my = new CipherEntry("my", h);

     JPanel p = new JPanel();
     p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
     p.add(my.getCipherCheckBox());
     p.add(my.getTokenComboBox());
     p.add(my.getCertComboBox());

     f.getContentPane().add(p);
     f.setSize(400,400);
     f.show();
     }*/
}

