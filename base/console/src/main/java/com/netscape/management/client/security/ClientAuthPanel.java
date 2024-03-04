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


import java.awt.*;
import java.util.*;
import java.awt.event.*;
import javax.swing.*;
import com.netscape.management.client.util.*;

/**
 *
 *
 *
 * @see com.netscape.management.client.security.IClientAuthOptions
 *
 */

public class ClientAuthPanel extends JPanel implements ActionListener{

    /*static ClientAuthPanel cap;
    public static void main(String args[]) {
        try {
            UIManager.setLookAndFeel(new SuiLookAndFeel());
        } catch (Exception e) {}

        JFrame f = new JFrame();
        f.getContentPane().setLayout(new FlowLayout());
        cap  = new ClientAuthPanel(new IClientAuthOptions() {

                public void clientAuthSettingChanged(int type) {
                    System.out.println(type);
                }
                public int getClientAuthSetting() {
                    return 0;
                }
                public int[] getClientAuthUIOption() {
                    return IClientAuthOptions.DEFAULT_CLIENT_AUTH_UI_OPTIONS;
                    //int[] uiOptions = { IClientAuthOptions.CLIENT_AUTH_DISABLED, IClientAuthOptions.CLIENT_AUTH_REQUIRED };
                    //return uiOptions;
                }
            });
        f.getContentPane().add(cap);

        JButton b = new JButton("reset");
        JButton s = new JButton("save");
        b.addActionListener(new ActionListener() {public void actionPerformed(ActionEvent e) {ClientAuthPanel.cap.reset();}});
        f.getContentPane().add(b);
        s.addActionListener(new ActionListener() {public void actionPerformed(ActionEvent e) {ClientAuthPanel.cap.setSaved();}});
        f.getContentPane().add(s);

        f.pack();
        f.show();
    }*/


    IClientAuthOptions iClientAuthOption;
    ButtonModel resetValue;
    JRadioButton disabled, enabled, required;
    ButtonGroup buttonGroup;


    private static String i18n(String id)
    {
        return SecurityUtil.getResourceSet().getString("ClientAuthPanel", id);
    }

    /**
     * Reset client options to initial settings
     */
    public void reset() {
        buttonGroup.setSelected(resetValue, true);
        resetValue.setSelected(true);
	Debug.println("ClientAuthPanel.reset:"+resetValue);
    }

    /**
     * Call this function after the setting has been saved, so
     * if reset is called it will not revert to the initial
     * value (value before it has been saved).
     */
    public void setSaved() {
        resetValue = buttonGroup.getSelection();
	Debug.println("ClientAuthPanel.setSaved:"+resetValue);
    }


    /**
     * enable or disable client ui.
     * 
     * @param enable true to enable all buttons, false to disable and gray out all buttons
     */
    public void setEnabled(boolean enable) {
	Enumeration button_enum = buttonGroup.getElements();
	while (button_enum.hasMoreElements()) {
	    ((JRadioButton)(button_enum.nextElement())).setEnabled(enable);
	}
    }

    /**
     *
     * Create an client authentication setting panel
     *
     * @param clientAuthOptions interface that allow client authentication setting panel to
     *                             query for setting, and send change events when it occures
     */
    public ClientAuthPanel(IClientAuthOptions clientAuthOptions) {
        super();

        setLayout(new GridBagLayout());

        iClientAuthOption = clientAuthOptions;


        int[] uiOptions = iClientAuthOption.getClientAuthUIOption();

        buttonGroup = new ButtonGroup();

        int y = 0;
        for (int i=0; i<uiOptions.length; i++) {
            JRadioButton button = null;
            switch (uiOptions[i]) {
            case IClientAuthOptions.CLIENT_AUTH_DISABLED:
                disabled = new JRadioButton(i18n("disableLabel"), (iClientAuthOption.getClientAuthSetting()==IClientAuthOptions.CLIENT_AUTH_DISABLED));
                disabled.setActionCommand("DISABLED");
                button = disabled;
                break;
            case IClientAuthOptions.CLIENT_AUTH_ALLOWED:
                enabled  = new JRadioButton(i18n("allowLabel") , (iClientAuthOption.getClientAuthSetting()==IClientAuthOptions.CLIENT_AUTH_ALLOWED));
                enabled.setActionCommand("ENABLED");
                button = enabled;
                break;
            case IClientAuthOptions.CLIENT_AUTH_REQUIRED:
                required = new JRadioButton(i18n("requireLabel"), (iClientAuthOption.getClientAuthSetting()==IClientAuthOptions.CLIENT_AUTH_REQUIRED));
                required.setActionCommand("REQUIRED");
                button = required;
                break;
            }

            button.addActionListener(this);
            buttonGroup.add(button);
            GridBagUtil.constrain(this, button, 0, ++y, 1, 1, 1.0, 0.0,
                                  GridBagConstraints.NORTH, GridBagConstraints.HORIZONTAL,
                                  0, 0, 0, 0);
        }


        setSaved();

    }


    public void actionPerformed(ActionEvent e) {
        if (e.getActionCommand().equals("ENABLED")) {
            iClientAuthOption.clientAuthSettingChanged(IClientAuthOptions.CLIENT_AUTH_ALLOWED);
        } else if (e.getActionCommand().equals("DISABLED")) {
            iClientAuthOption.clientAuthSettingChanged(IClientAuthOptions.CLIENT_AUTH_DISABLED);
        } else if (e.getActionCommand().equals("REQUIRED")) {
            iClientAuthOption.clientAuthSettingChanged(IClientAuthOptions.CLIENT_AUTH_REQUIRED);
        }
    }
}
