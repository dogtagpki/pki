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

import java.awt.Component;
import java.awt.Container;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import com.netscape.management.nmclf.SuiLookAndFeel;


/**
 * Provides a set of convenience methods to set
 * parameters for GridBagLayout.
 */
public class GridBagUtil extends Object {

    /**
     * Utility routine to setup the GridBagConstraints for a container using
     * GridBagLayout. The component is added to the container using the
     * provided constraint parameters.
    *
    * @param container  container object
    * @param component  component object to add to container
    * @param gx         grid x
    * @param gy         grid y
    * @param gw         grid width
    * @param gh         grid height
    * @param wx         weight x
    * @param wy         weight y
    * @param a          anchor
    * @param f          fill
    * @param top        top inset
    * @param left       left inset
    * @param bottom     bottom inset
    * @param right      right inset
     */
    public static void constrain(Container container,
            Component component, int gx, int gy, int gw, int gh,
            double wx, double wy, int a, int f, int top, int left,
            int bottom, int right) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = gx;
        c.gridy = gy;
        c.gridwidth = gw;
        c.gridheight = gh;
        c.weightx = wx;
        c.weighty = wy;
        c.anchor = a;
        c.fill = f;
        if (top + left + bottom + right > 0) {
            c.insets = new Insets(top, left, bottom, right);
        }
        ((GridBagLayout) container.getLayout()).setConstraints(
                component, c);
        container.add(component);
    }


    /**
      * Utility routine to setup the GridBagConstraints for a container using
      * GridBagLayout. The component is added to the container using the
      * provided constraint parameters. This version uses the SuiLookAndFeel
      * DIFFERENT_COMPONENT_SPACE as the default insets.
     *
     * @param container  container object
     * @param component  component object to add to container
     * @param gx         grid x
     * @param gy         grid y
     * @param gw         grid width
     * @param gh         grid height
     * @param wx         weight x
     * @param wy         weight y
     * @param a          anchor
     * @param f          fill
      */
    public static void constrain(Container container,
            Component component, int gx, int gy, int gw, int gh,
            double wx, double wy, int a, int f) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = gx;
        c.gridy = gy;
        c.gridwidth = gw;
        c.gridheight = gh;
        c.weightx = wx;
        c.weighty = wy;
        c.anchor = a;
        c.fill = f;
        c.insets = new Insets(SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE,
                SuiLookAndFeel.DIFFERENT_COMPONENT_SPACE);
        ((GridBagLayout) container.getLayout()).setConstraints(
                component, c);
        container.add(component);
    }
}
