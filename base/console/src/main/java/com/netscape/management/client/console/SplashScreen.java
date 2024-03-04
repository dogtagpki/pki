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
package com.netscape.management.client.console;

import java.awt.*;
import javax.swing.*;
import javax.swing.border.*;
import com.netscape.management.client.util.*;
import com.netscape.management.nmclf.*;


/**
 * Displays a splash screen indicating the product
 * name and version.  For use with the Login sequence.
 */
public class SplashScreen extends JWindow implements SwingConstants,
SuiConstants {
    JLabel statusLabel = new JLabel(" ");
    static SplashScreen _instance = null;
    boolean _firstShow = true;

    /**
     * constructor
     *
     * @param f parent frame
     */
    public SplashScreen(Frame f) {
        super(f);
        _instance = this;
        Debug.println(Debug.TYPE_GC, Debug.KW_CREATE + "Splash Screen");
        populateContentPane(getContentPane());
        pack();
    }

    /**
      * this window cannot resize.
      *
      * @return not resizeable
      */
    public boolean isResizable() {
        return false;
    }

    /**
      * return the current instance of splash screen
      *
      * @return current instance
      */
    public static SplashScreen getInstance() {
        return _instance;
    }

    /**
      * remove current instance of splash screen
      */
    public static void removeInstance() {
        _instance.dispose();
        _instance = null;
    }


    protected void finalize() throws Throwable {
        Debug.println(Debug.TYPE_GC, Debug.KW_FINALIZE + "Splash Screen");
        super.finalize();
    }

    /**
      * show the splash screen
      */
    public void showWindow() {
        centerOnScreen();
        this.setVisible(true);
        Debug.println(Debug.TYPE_RSPTIME, "Splash screen shown");
    }

    /**
      * hide the splash screen
      */
    public void hide() {
        super.hide();
        /** We need to call removeNotify() here because hide() does something only if
         *  Component.visible is true. When the app frame is miniaturized, the parent
         *  frame of this frame is invisible, causing AWT to believe that this frame
         *  is invisible and causing hide() to do nothing
         */
        removeNotify();
    }

    /**
      * set the status text in the splash screen.
      *
      * @param text text to be displayed
      */
    public void setStatusText(String text) {
        statusLabel.setText(text);
        statusLabel.getParent().doLayout();
    }

    /**
      * create the splash screen content.
      *
      * @param contentPane splash screen's content pane
      */
    protected void populateContentPane(Container contentPane) {
        JPanel panel = new JPanel();
        Border margin = new EmptyBorder(3, 3, 3, 3);
        Border raised = new BevelBorder(BevelBorder.RAISED);
        Border lowered = new BevelBorder(BevelBorder.LOWERED);
        Border border1 = new CompoundBorder(raised, margin);
        Border border = new CompoundBorder(border1, lowered);
        panel.setBorder(border);

        GridBagLayout gridbag = new GridBagLayout();
        panel.setLayout(gridbag);
        panel.setBackground(Color.white);

        GridBagConstraints c = new GridBagConstraints();

        JLabel splashLabel = new JLabel(new RemoteImage("com/netscape/management/client/theme/images/login.gif"));
        c.gridwidth = 1;
        c.gridheight = 1;
        c.gridx = 0;
        c.gridy = 0;
        c.insets = new Insets(0, 0, 0, 0);
        c.fill = GridBagConstraints.NONE;
        c.weightx = 0.0;
        c.weighty = 0.0;
        c.anchor = GridBagConstraints.WEST;
        gridbag.setConstraints(splashLabel, c);
        panel.add(splashLabel);

        statusLabel.setForeground(Color.white);
        statusLabel.setBackground(Color.black);
        statusLabel.setOpaque(true);
        statusLabel.setHorizontalAlignment(CENTER);
        statusLabel.setBorder(
                new EmptyBorder(COMPONENT_SPACE, HORIZ_WINDOW_INSET,COMPONENT_SPACE,
                HORIZ_WINDOW_INSET));
        statusLabel.setFont(UIManager.getFont("Status.font"));
        c.gridwidth = 1;
        c.gridheight = 1;
        c.gridx = 0;
        c.gridy = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1.0;
        c.weighty = 0.0;
        c.anchor = GridBagConstraints.SOUTH;
        gridbag.setConstraints(statusLabel, c);
        panel.add(statusLabel);

        contentPane.add("Center", panel);
    }

    /**
      * Sets the location of the dialog relative to the specified
      * component. If the component is not currently showing, the
      * dialog is centered on the screen.
      */
    private void centerOnScreen() {
        Dimension paneSize = getSize();
        Dimension screenSize = getToolkit().getScreenSize();

        setLocation((screenSize.width - paneSize.width) / 2,
                (screenSize.height - paneSize.height) / 2);
    }
}
