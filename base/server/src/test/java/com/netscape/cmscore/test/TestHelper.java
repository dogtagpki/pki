package com.netscape.cmscore.test;

import java.util.Enumeration;

/**
 * Testing helper methods
 */
public class TestHelper {

    public static boolean enumerationContains(Enumeration<?> enumeration,
                                              Object element) {
        while (enumeration.hasMoreElements()) {
            if (enumeration.nextElement().equals(element)) {
                return true;
            }
        }
        return false;
    }

    public static boolean contains(String[] list, String element) {
        for (int index = 0; index < list.length; index++) {
            if (list[index].equals(element)) {
                return true;
            }
        }

        return false;
    }

}
