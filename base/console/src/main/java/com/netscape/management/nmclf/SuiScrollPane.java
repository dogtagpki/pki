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
package com.netscape.management.nmclf;

import java.awt.*;
import javax.swing.*;

/**
 * An extension of JScrollPane to address this problem:
 * Scrolling by dragging the slider causes the JScrollPane
 * contents to be continually updated.  This occurs because
 * of a bug in BoundedRangeModel, which has been fixed in
 * SuiBoundedRangeModel.  SuiScrollPane is needed  so that
 * it can make use of SuiBoundedRangeModel.
 *
 * This continous update behavior can be re-instated
 * by calling setUpdateWhileAdjusting(true) method.
 *
 * @author ahakim@netscape.com
 * @see SuiBoundedRangeModel
 */
public class SuiScrollPane extends JScrollPane {
    SuiBoundedRangeModel _boundedRangeModel;

    public SuiScrollPane(Component view, int vsbPolicy, int hsbPolicy) {
        super(view, vsbPolicy, hsbPolicy);
    }

    public SuiScrollPane(Component view) {
        this(view, VERTICAL_SCROLLBAR_AS_NEEDED,
                HORIZONTAL_SCROLLBAR_AS_NEEDED);
    }

    public SuiScrollPane(int vsbPolicy, int hsbPolicy) {
        this(null, vsbPolicy, hsbPolicy);
    }

    public SuiScrollPane() {
        this(null, VERTICAL_SCROLLBAR_AS_NEEDED,
                HORIZONTAL_SCROLLBAR_AS_NEEDED);
    }

    //    public JScrollBar createHorizontalScrollBar()
    //	{
    //        return new SuiScrollBar(JScrollBar.HORIZONTAL);
    //    }

    public JScrollBar createVerticalScrollBar() {
        return new SuiScrollBar(JScrollBar.VERTICAL);
    }

    /**
      * Controls whether contents should scroll in real-time as
      * the scroll bar slider is dragged.  If false (default), then
      * the contents is only changed after the drag is completed.
      */
    public void setUpdateWhileAdjusting(boolean state) {
        _boundedRangeModel.setUpdateWhileAdjusting(state);
    }

    /**
      * Returns true if contents should scroll in real-time as
      * the scroll bar slider is dragged.
      */
    public boolean getUpdateWhileAdjusting() {
        return _boundedRangeModel.getUpdateWhileAdjusting();
    }

    /**
      * THIS is an extension of JScrollBar.ScrollBar()
      *
      */
    class SuiScrollBar extends JScrollBar {
        public SuiScrollBar(int orientation, int value, int extent,
                int min, int max) {
            checkOrientation(orientation);
            unitIncrement = 1;
            blockIncrement = (extent == 0) ? 1 : extent;
            orientation = orientation;
            //model = new DefaultBoundedRangeModel(value, extent, min, max);
            //this.model.addChangeListener(fwdAdjustmentEvents);
            _boundedRangeModel =
                    new SuiBoundedRangeModel(value, extent, min, max);
            setModel(_boundedRangeModel);
            updateUI();
            //super(orientation, value, extent, min, max);
        }

        private void checkOrientation(int orientation) {
            switch (orientation) {
            case VERTICAL:
            case HORIZONTAL:
                break;
            default:
                throw new IllegalArgumentException("orientation must be one of: VERTICAL, HORIZONTAL");
            }
        }

        public SuiScrollBar(int orientation) {
            this(orientation, 0, 10, 0, 100);
        }

        public SuiScrollBar() {
            this(VERTICAL);
        }

        /**
          * THIS COMES FROM JScrollBar.ScrollBar()
          *
          * If the viewports view is a Scrollable then ask the view
          * to compute the unit increment.  Otherwise return
          * super.getUnitIncrement().
          *
          * @see Scrollable#getScrollableUnitIncrement
          */
        public int getUnitIncrement(int direction) {
            JViewport vp = getViewport();
            if ((vp != null) && (vp.getView() instanceof Scrollable)) {
                Scrollable view = (Scrollable)(vp.getView());
                Rectangle vr = vp.getViewRect();
                return view.getScrollableUnitIncrement(vr,
                        getOrientation(), direction);
            } else {
                return super.getUnitIncrement(direction);
            }
        }

        /**
          * THIS COMES FROM JScrollBar.ScrollBar()
          *
          * If the viewports view is a Scrollable then ask the
          * view to compute the block increment.  Otherwise
          * the blockIncrement equals the viewports width
          * or height.  If there's no viewport reuurn
          * super.getBlockIncrement().
          *
          * @see Scrollable#getScrollableBlockIncrement
          */
        public int getBlockIncrement(int direction) {
            JViewport vp = getViewport();
            if (vp == null) {
                return super.getBlockIncrement(direction);
            } else if (vp.getView() instanceof Scrollable) {
                Scrollable view = (Scrollable)(vp.getView());
                Rectangle vr = vp.getViewRect();
                return view.getScrollableBlockIncrement(vr,
                        getOrientation(), direction);
            } else if (getOrientation() == VERTICAL) {
                return vp.getExtentSize().width;
            } else {
                return vp.getExtentSize().height;
            }
        }
    }
}
