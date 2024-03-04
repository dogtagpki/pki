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
package com.netscape.management.client.util;

import java.awt.*;
import javax.swing.JDialog;


/**
 * A set of utility methods to handle modal dialog disposal.
 * These address Swing 1.0 repaint problems on NT, as well as the
 * Frame being placed in the background.
 *
 * @todo  remove because problems are either fixed or part of AbstractDialog
 */
public class ModalDialogUtil {

    /**
     * Utility routine to dispose the passed in JDialog and sleep.
     *
     * @param d  dialog to dispose
     */
    public static void dispose(JDialog d) {
        if (d != null)
            d.dispose();
        ModalDialogUtil.sleep(200);
    }


    /**
      * Utility routine to dispose the passed in JDialog and raise to front
      * the passed in Frame.
      *
      * @param d  JDialog to dispose
      * @param f  Frame to raise to front
      */
    public static void disposeAndRaise(JDialog d, Frame f) {
        if (d != null)
            d.dispose();
        ModalDialogUtil.sleep(200);
        ModalDialogUtil.raise(f);
    }


    /**
      * Utility routine to raise the passed in JDialog and sleep.
      *
      * @param f  the Frame to raise
      */
    public static void raise(Frame f) {
        if (f != null) {
            f.toFront();
            f.repaint();
        }
    }


    /**
      * Utility routine to sleep for a 200 ms.
      */
    public static void sleep() {
        ModalDialogUtil.sleep(200);
    }


    /**
      * Utility routine to sleep for a specified amount of time.
      *
      * @param tm  sleep for the duration of time in milliseconds
      */
    public static void sleep(int tm) {
        if (tm <= 0)
            return;

        // Pause to get around repaint problem.
        try {
            Thread.sleep(tm);
        } catch (Exception exc) {
            Debug.println(0, "ERROR ModalDialogUtil: exception: " + exc);
        }
    }


    // In case not visible components are passed as a parent to showDialog(),
    // we create an helper Window to use as a parent.
    private static Window _helperWindow;

    /**
     * Return the component's showing ancestor. If one does not exist,
     * use the helper window.
     *
     * @param c  component whose ancestor is to be shown
     */
    public static Component getShowingAncestor(Component c) {
        while (c != null && !c.isShowing() && c.getParent() != null) {
            c = c.getParent();
        }

        if (c == null)
            c = UtilConsoleGlobals.getActivatedFrame();

        if (c == null || !c.isShowing()) {
            if (_helperWindow == null) {
                _helperWindow = new Window (new Frame());
            }
            if (!_helperWindow.isVisible()) {
                _helperWindow.setBounds(0, 0, 0, 0);
                _helperWindow.setVisible(true);
            }
            c = _helperWindow;
        }
        return c;
    }

    /**
      * Position the dialog on the screen in respect to its parent
      * @param dialog A compoenent to center
      * @parent parent component or null (center to the last activated frame)
      */
    public static void setDialogLocation(Component dialog,
            Component parent) {
        Component refComp = getShowingAncestor(parent);
        Point pXY = refComp.getLocationOnScreen(), myXY = new Point();
        Dimension pWH = refComp.getSize();
        Dimension myWH = dialog.getSize();
        Dimension scrWH = Toolkit.getDefaultToolkit().getScreenSize();

        // Default is to center dialog in respect to parent location
        if (myWH.width < pWH.width || myWH.height < pWH.height) {
            myXY.x = pXY.x + (pWH.width - myWH.width) / 2;
            myXY.y = pXY.y + (pWH.height - myWH.height) / 2;
        } else { // Dialog would hide it's parent, offset dialog's location to the parent
            myXY.x = pXY.x + 20;
            myXY.y = pXY.y + 20;
        }

        // make sure the dialog is completly visible
        if (myXY.x < 0)
            myXY.x = 0;
        if (myXY.y < 0)
            myXY.y = 0;
        if ((myXY.x + myWH.width) > scrWH.width)
            myXY.x = scrWH.width - myWH.width;
        if ((myXY.y + myWH.height) > scrWH.height)
            myXY.y = scrWH.height - myWH.height;

        dialog.setLocation(myXY);
    }

    /**
      * Center the window on the screen.
      *
      * @param win  window whose location is to be set
      */
    public static void setWindowLocation(Component win) {
        win.setLocation(calcWindowLocation(win.getSize()));
    }

    /**
      * Calculate the window location based on its size.
      *
      * @param winSize  window size to base its location off of
      * @return         the window location
      */
    public static Point calcWindowLocation(Dimension winSize) {
        Point winXY = new Point();
        Dimension scrWH = Toolkit.getDefaultToolkit().getScreenSize();

        winXY.x = (scrWH.width - winSize.width) / 2;
        winXY.y = (scrWH.height - winSize.height) / 2;

        if ((winXY.x + winSize.width) > scrWH.width)
            winXY.x = 0;
        if ((winXY.y + winSize.height) > scrWH.height)
            winXY.y = 0;

        return winXY;
    }


    /**
      * Center the dialog on the screen.
      *
      * @param dialog dialog to center
      */
    public static void setCenteredDialog(Component dialog) {
        Dimension paneSize = dialog.getSize();
        Dimension screenSize = dialog.getToolkit().getScreenSize();

        dialog.setLocation((screenSize.width - paneSize.width) / 2,
                (screenSize.height - paneSize.height) / 2);
    }

}
