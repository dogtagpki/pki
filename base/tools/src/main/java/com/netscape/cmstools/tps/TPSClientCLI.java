//
// Copyright Red Hat, Inc.
//
// SPDX-License-Identifier: GPL-2.0-or-later
//
package com.netscape.cmstools.tps;

import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.lang3.StringUtils;
import org.dogtagpki.cli.CommandCLI;

import com.netscape.cmstools.cli.MainCLI;

/**
 * @author Endi S. Dewata
 */
public class TPSClientCLI extends CommandCLI {

    public static org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(TPSClientCLI.class);

    static {
        System.loadLibrary("pki-tps");
    }

    public TPSCLI tpsCLI;

    public TPSClientCLI(TPSCLI tpsCLI) {
        super("client", "TPS client", tpsCLI);
        this.tpsCLI = tpsCLI;
    }

    @Override
    public void printHelp() {
        formatter.printHelp(getFullName() + " [OPTIONS...]", options);
    }

    public Map<String, String> parse(String line) {

        logger.info("Parsing " + line);

        Map<String, String> map = new HashMap<>();

        for (String param : line.split(" ")) {

            String[] parts = param.split("=", 2);
            String key = parts[0];
            String value = parts[1];
            logger.info("- " + key + ": " + value);

            map.put(key, value);
        }

        return map;
    }

    public native long createClient() throws Exception;
    public native void removeClient(long client) throws Exception;

    public native boolean getOldStyle(long client) throws Exception;
    public native void setOldStyle(long client, boolean value) throws Exception;

    public native void displayHelp(long client) throws Exception;

    public native void performFormatToken(long client, Map<String, String> params) throws Exception;

    public void oldFormatToken(
            long client,
            Map<String, String> params)
            throws Exception {

        String value = params.get("num_threads");
        int numThreads = value == null ? 1 : Integer.parseInt(value);

        Thread[] threads = new Thread[numThreads];
        Exception[] exceptions = new Exception[numThreads];

        // start threads
        for (int i=0; i<numThreads; i++) {

            int index = i;

            threads[i] = new Thread(new Runnable() {
                public void run() {
                    try {
                        performFormatToken(client, params);
                    } catch (Exception e) {
                        exceptions[index] = e;
                    }
                }
            });

            threads[i].start();
        }

        // wait for threads to complete
        for (int i=0; i<numThreads; i++) {
            threads[i].join();
        }

        // check for exceptions
        for (int i=0; i<numThreads; i++) {
            if (exceptions[i] != null) throw exceptions[i];
        }
    }

    public native void newFormatToken(long client, Map<String, String> params) throws Exception;

    public void formatToken(
            long client,
            Map<String, String> params)
            throws Exception {

        if (getOldStyle(client)) {
            oldFormatToken(client, params);
        } else {
            newFormatToken(client, params);
        }
    }

    public native void performResetPIN(long client, Map<String, String> params) throws Exception;

    public void oldResetPIN(
            long client,
            Map<String, String> params)
            throws Exception {

        String value = params.get("num_threads");
        int numThreads = value == null ? 1 : Integer.parseInt(value);

        Thread[] threads = new Thread[numThreads];
        Exception[] exceptions = new Exception[numThreads];

        // start threads
        for (int i=0; i<numThreads; i++) {

            int index = i;

            threads[i] = new Thread(new Runnable() {
                public void run() {
                    try {
                        performResetPIN(client, params);
                    } catch (Exception e) {
                        exceptions[index] = e;
                    }
                }
            });

            threads[i].start();
        }

        // wait for threads to complete
        for (int i=0; i<numThreads; i++) {
            threads[i].join();
        }

        // check for exceptions
        for (int i=0; i<numThreads; i++) {
            if (exceptions[i] != null) throw exceptions[i];
        }
    }

    public native void newResetPIN(long client, Map<String, String> params) throws Exception;

    public void resetPIN(
            long client,
            Map<String, String> params)
            throws Exception {

        if (getOldStyle(client)) {
            oldResetPIN(client, params);
        } else {
            newResetPIN(client, params);
        }
    }

    public native void performEnrollToken(long client, Map<String, String> params) throws Exception;

    public void oldEnrollToken(
            long client,
            Map<String, String> params)
            throws Exception {

        String value = params.get("num_threads");
        int numThreads = value == null ? 1 : Integer.parseInt(value);

        Thread[] threads = new Thread[numThreads];
        Exception[] exceptions = new Exception[numThreads];

        // start threads
        for (int i=0; i<numThreads; i++) {

            int index = i;

            threads[i] = new Thread(new Runnable() {
                public void run() {
                    try {
                        performEnrollToken(client, params);
                    } catch (Exception e) {
                        exceptions[index] = e;
                    }
                }
            });

            threads[i].start();
        }

        // wait for threads to complete
        for (int i=0; i<numThreads; i++) {
            threads[i].join();
        }

        // check for exceptions
        for (int i=0; i<numThreads; i++) {
            if (exceptions[i] != null) throw exceptions[i];
        }
    }

    public native void newEnrollToken(long client, Map<String, String> params) throws Exception;

    public void enrollToken(
            long client,
            Map<String, String> params)
            throws Exception {

        if (getOldStyle(client)) {
            oldEnrollToken(client, params);
        } else {
            newEnrollToken(client, params);
        }
    }

    public native void displayToken(long client, Map<String, String> params) throws Exception;
    public native void setupToken(long client, Map<String, String> params) throws Exception;

    public native void setupDebug(long client, Map<String, String> params) throws Exception;
    public native void setVariable(long client, Map<String, String> params) throws Exception;
    public native void displayVariable(long client, Map<String, String> params) throws Exception;
    public native void listVariables(long client) throws Exception;

    public void invokeOperation(
            long client,
            String op,
            Map<String, String> params)
            throws Exception {

        String value = params.get("max_ops");
        int maxOps = value == null ? 0 : Integer.parseInt(value);

        if (maxOps != 0) {
            setOldStyle(client, false);
        }

        if ("help".equals(op)) {
            displayHelp(client);

        } else if ("ra_format".equals(op)) {
            formatToken(client, params);

        } else if ("ra_reset_pin".equals(op)) {
            resetPIN(client, params);

        } else if ("ra_enroll".equals(op)) {
            enrollToken(client, params);

        } else if ("token_status".equals(op)) {
            displayToken(client, params);

        } else if ("token_set".equals(op)) {
            setupToken(client, params);

        } else if ("debug".equals(op)) {
            setupDebug(client, params);

        } else if ("var_set".equals(op)) {
            setVariable(client, params);

        } else if ("var_get".equals(op)) {
            displayVariable(client, params);

        } else if ("var_list".equals(op)) {
            listVariables(client);

        } else {
            logger.error("Unsupported operation: " + op);
            // continue to the next operation
        }
    }

    @Override
    public void execute(CommandLine cmd) throws Exception {

        MainCLI mainCLI = (MainCLI) getRoot();
        mainCLI.init();

        System.out.println("TPS Client");
        System.out.println("'op=help' for Help");

        long client = createClient();

        try (Scanner input = new Scanner(System.in)) {
            while (true) {
                System.out.print("Command> ");
                System.out.flush();

                String line = input.nextLine();

                if (line == null) {
                    break;
                }

                System.out.println(line);

                if (StringUtils.isBlank(line)) {
                    continue;
                }

                if (line.startsWith("#")) {
                    continue;
                }

                Map<String, String> params = parse(line);
                String op = params.get("op");

                if ("exit".equals(op)) {
                    break;
                }

                invokeOperation(client, op, params);
            }

        } finally {
            removeClient(client);
        }
    }
}
