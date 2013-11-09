package com.netscape.beakertests;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

/**
 * Super class for all the test classes.
 * Provides common functionality for logging messages and
 * providing asserts and getting the test environment parameters
 * @author akoneru
 *
 */
public class PKIJUnitTest {

    public static String INFO = "rlLogInfo";
    public static String DEBUG = "rlLogDebug";
    public static String WARNING = "rlLogWarning";
    public static String ERROR = "rlLogError";
    public static String CRITICAL = "rlLogFatal";

    private BeakerScript beakerScript;
    String logLevel;
    Properties properties;
    private boolean run_with_beaker = false;

    public PKIJUnitTest() {
        String runWithBeaker = System.getenv("RUNNING_WITH_BEAKER");
        if (runWithBeaker == null || (! runWithBeaker.toLowerCase().equals("true"))) {
            properties = new Properties();
            try {
                properties.load(new BufferedReader(new FileReader("tests/dogtag/conf/test.cfg")));
            } catch (IOException e) {
                e.printStackTrace();
                System.err.println("Cannot read the configuration file");
                System.exit(-1);
            }
        } else {
            run_with_beaker = true;
            beakerScript = BeakerScript.getInstance();
            logLevel = INFO;
        }
    }

    public void setLogLevel(String logLevel) {
        this.logLevel = logLevel;
    }

    public void log(String message) {
        if (run_with_beaker) {
            beakerScript.addBeakerCommand(new String[] { logLevel, message });
            return;
        }
        System.out.println(message);
    }

    /**
     * Use this method to add asserts to the beaker output.
     *
     * @param hasPassed
     * @param comment
     */
    public void beakerAssert(boolean hasPassed, String comment) {
        if (comment == null) {
            comment = "";
        }
        if (hasPassed) {
            beakerScript.addBeakerCommand(new String[] { "rlPass", comment });
        } else {
            beakerScript.addBeakerCommand(new String[] { "rlFail", comment });
        }
    }

    /**
     * All the configuration entries are set as environment variables when run in beaker.
     * Similar key-value pairs are found in the configuration file when running the tests in eclipse
     * on a local setup.
     * @param key
     * @return
     */
    public String getParameter(String key) {
        if (run_with_beaker) {
            return System.getenv(key);
        }
        return properties.getProperty(key);
    }

}
