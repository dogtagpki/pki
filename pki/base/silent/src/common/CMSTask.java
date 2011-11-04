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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;


/**
 * CS Test framework .
 * This class starts and stops CS server from command line  
 */

public class CMSTask {

    private static String operation;
    private static String debug;
    private static String serverRoot;
    private Process p = null;

    /**
     * Constructor . Takes CMS server root as parameter  
     * for example (/export/qa/cert-jupiter2)
     **/

    public CMSTask() {// do nothing
    }

    public CMSTask(String sroot) {
        serverRoot = sroot;
    }

    public boolean CMSStart() {

        try {
            System.out.println("Starting Certificate System:");
            Runtime r = Runtime.getRuntime();

            p = r.exec(serverRoot + "/start-cert");

            InputStreamReader isr = new InputStreamReader(p.getInputStream());
            BufferedReader br = new BufferedReader(isr);
            String s = null;

            try {
                while ((s = br.readLine()) != null) {
                    if (s.indexOf("started") > 0) { 
                        return true;
                    }
                    // do something
                }
            } catch (IOException ioe) {
                ioe.printStackTrace();
            }

            return false;

        } catch (Throwable e) {
            e.printStackTrace();
        }

        return false;
    }

    public boolean CMSStop() {
        try {
            Runtime r = Runtime.getRuntime();

            System.out.println("Stopping Certificate System:");
            p = r.exec(serverRoot + "/stop-cert");
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(p.getInputStream()));
            String line;

            while ((line = br.readLine()) != null) {
                System.out.println("     " + line);
                if (line.indexOf("server shut down") > -1) {
                    return true;
                } else {
                    return false;
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean CMSRestart() {
        try {
            System.out.println("Restarting Certificate System:");
            Runtime r = Runtime.getRuntime();

            p = r.exec(serverRoot + "/restart-cert");
            BufferedReader br = new BufferedReader(
                    new InputStreamReader(p.getInputStream()));
            String line;

            while ((line = br.readLine()) != null) {
                System.out.println("     " + line);
                if (line.indexOf("started") > -1) {
                    return true;
                } else {
                    return false;
                }
            }

        } catch (Throwable e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean task() {
        if (operation.equalsIgnoreCase("stop")) {
            CMSStop();
            return true;
        }

        if (operation.equalsIgnoreCase("start")) {
            CMSStart();
            return true;
        }

        if (operation.equalsIgnoreCase("restart")) {
            CMSRestart();
            return true;
        }

        return false;
    }

    public static void main(String args[]) {
        CMSTask prof = new CMSTask();
        // parse args
        StringHolder x_instance_root = new StringHolder();
        StringHolder x_operation = new StringHolder();

        // parse the args
        ArgParser parser = new ArgParser("CMSTask");

        parser.addOption("-instance_root %s #CA Server Root", x_instance_root);
        parser.addOption("-operation %s #CA operation [stop,start,restart]",
                x_operation);

        // and then match the arguments
        String[] unmatched = null;

        unmatched = parser.matchAllArgs(args, 0, parser.EXIT_ON_UNMATCHED);

        if (unmatched != null) {
            System.out.println("ERROR: Argument Mismatch");
            System.exit(-1);
        }

        // set variables
        serverRoot = x_instance_root.value;
        operation = x_operation.value;
		
        boolean st = prof.task();

        if (!st) {
            System.out.println("ERROR");
        }

        System.out.println("SUCCESS");

    } // end of function main

} // end of class 

