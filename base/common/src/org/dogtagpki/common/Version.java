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

    public static void main(String args[]) throws Exception {
        Version version = new Version("10.4.0");
        if (version.getMajor() != 10) System.out.println("Error in getting major");
        if (version.getMinor() != 4) System.out.println("Error in getting minor");
        if (version.getMicro() != 0) System.out.println("Error in getting micro");

        version = new Version("9.1");
        if (version.getMajor() != 9) System.out.println("Error in getting major");
        if (version.getMinor() != 1) System.out.println("Error in getting minor");
        if (version.getMicro() != 0) System.out.println("Error in getting micro");

        version = new Version("4");
        if (version.getMajor() != 4) System.out.println("Error in getting major");
        if (version.getMinor() != 0) System.out.println("Error in getting minor");
        if (version.getMicro() != 0) System.out.println("Error in getting micro");

        version = new Version("8.53.2.6");
        if (version.getMajor() != 8) System.out.println("Error in getting major");
        if (version.getMinor() != 53) System.out.println("Error in getting minor");
        if (version.getMicro() != 2) System.out.println("Error in getting micro");
    }

}
