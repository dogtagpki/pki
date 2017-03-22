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
// (C) 2017 Red Hat, Inc.
// All rights reserved.
// --- END COPYRIGHT BLOCK ---

package org.dogtagpki.common;

public class Version {

    private int major;
    private int minor;
    private int micro;

    public Version(String version) {
        String[] parts = version.split("[.]");
        major = Integer.valueOf(parts[0]);

        if (parts.length > 1) {
            minor = Integer.valueOf(parts[1]);
        }
        if (parts.length > 2) {
            micro = Integer.valueOf(parts[2]);
        }
    }

    public int getMajor() {
        return major;
    }

    public void setMajor(int major) {
        this.major = major;
    }

    public int getMinor() {
        return minor;
    }

    public void setMinor(int minor) {
        this.minor = minor;
    }

    public int getMicro() {
        return micro;
    }

    public void setMicro(int micro) {
        this.micro = micro;
    }

    public int compare(Version v1, Version v2) {
        if (v1.major != v2.major) {
            return v1.major - v2.major;
        }
        if (v1.minor != v2.minor) {
            return v1.minor - v2.minor;
        }
        if (v1.micro != v2.micro) {
            return v1.micro - v2.micro;
        }
        return 0;
    }

    public boolean equals(Version v2) {
        return (compare(this, v2) == 0);
    }

    public boolean isNewerThan(Version v2) {
        return (compare(this, v2) > 0);
    }

    public boolean isOlderThan(Version v2) {
        return (compare(this, v2) < 0);
    }

    public boolean isNewerThanOrEquals(Version v2) {
        return (compare(this, v2) >=0);
    }

    public static void main(String args[]) throws Exception {
        Version v1 = new Version("10.4.0");
        if (v1.getMajor() != 10) System.out.println("Error in getting major");
        if (v1.getMinor() != 4) System.out.println("Error in getting minor");
        if (v1.getMicro() != 0) System.out.println("Error in getting micro");

        Version v2 = new Version("9.1");
        if (v2.getMajor() != 9) System.out.println("Error in getting major");
        if (v2.getMinor() != 1) System.out.println("Error in getting minor");
        if (v2.getMicro() != 0) System.out.println("Error in getting micro");

        Version v3 = new Version("4");
        if (v3.getMajor() != 4) System.out.println("Error in getting major");
        if (v3.getMinor() != 0) System.out.println("Error in getting minor");
        if (v3.getMicro() != 0) System.out.println("Error in getting micro");

        Version v4 = new Version("8.53.2.6");
        if (v4.getMajor() != 8) System.out.println("Error in getting major");
        if (v4.getMinor() != 53) System.out.println("Error in getting minor");
        if (v4.getMicro() != 2) System.out.println("Error in getting micro");

        // comparator tests
        if (!v1.isNewerThan(v2)) System.out.println("Error in isNewerThan comparator");
        if (!v4.isNewerThanOrEquals(v3)) System.out.println("Error in isNewerThanOrEquals comparator");
        if (!v1.equals(v1)) System.out.println("Error in equals comparator");
    }

}
