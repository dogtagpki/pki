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
import java.awt.image.*;
import javax.swing.*;

/**
 * Provides information about an ImageIcon.
 *
 * @author ahakim@netscape.com
 */
public class ImageInfo implements ImageObserver {
    private Image _image;
    private int _imageWidth;
    private int _imageHeight;

    public ImageInfo(ImageIcon imageIcon) {
        _image = imageIcon.getImage();
        _imageWidth = imageIcon.getIconWidth();
        _imageHeight = imageIcon.getIconHeight();
    }

    public ImageInfo(Image image) {
        _image = image;
        _imageWidth = image.getWidth(this);
        _imageHeight = image.getHeight(this);
    }

    public Color getTopRightAverageColor(int size) {
        int x = _imageWidth;
        int y = _imageHeight;
        return getAverageColor(x - size, y - size, size, size);
    }

    public Color getAverageColor(int x, int y, int w, int h) {
        int[] pixels = new int[w * h];
        int[] red = new int[w * h];
        int[] green = new int[w * h];
        int[] blue = new int[w * h];

        PixelGrabber pg =
                new PixelGrabber(_image, x, y, w, h, pixels, 0, w);
        try {
            pg.grabPixels();
        } catch (InterruptedException e) {
            Debug.println(0, "Interrupted waiting for pixels");
            return Color.black;
        }

        if ((pg.getStatus() & ImageObserver.ABORT) != 0) {
            Debug.println("Icon fetch aborted or errored");
            return Color.black;
        }

        for (int j = 0; j < h; j++) {
            for (int i = 0; i < w; i++) {
                int pixel = pixels[j * w + i];
                red[j * w + i] = (pixel >> 16) & 0xff;
                green[j * w + i] = (pixel >> 8) & 0xff;
                blue[j * w + i] = (pixel) & 0xff;
            }
        }
        return new Color(getAverage(red), getAverage(green),
                getAverage(blue));
    }

    protected int getAverage(int[] arrayARGB) {
        long sum = 0;

        for (int i = 0; i < arrayARGB.length; i++) {
            sum += arrayARGB[i];
        }
        return (int)(sum / arrayARGB.length);
    }


    // implements ImageObserver
    public boolean imageUpdate(Image img, int infoflags, int x, int y,
            int width, int height) {
        _imageWidth = width;
        _imageHeight = height;
        return true;
    }
}
