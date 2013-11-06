package com.netscape.beakertests;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;

import org.junit.runner.Description;
import org.junit.runner.Result;
import org.junit.runner.Runner;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunListener;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.Suite;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.RunnerBuilder;

/**
 * Custom Suite runner to provide functionality for when running in a beaker test
 * machine.
 * @author akoneru
 *
 */
public class PKITestSuite extends Suite {

    private BeakerScript beakerScript;
    private BeakerResultReporter bRR;
    private boolean run_with_beaker = false;

    public PKITestSuite(Class<?> klass, RunnerBuilder builder)
            throws InitializationError {
        super(klass, builder);
        String runWithBeaker = System.getenv("RUNNING_WITH_BEAKER");
        if (runWithBeaker != null && runWithBeaker.toLowerCase().equals("true")) {
            run_with_beaker = true;
            beakerScript = BeakerScript.getInstance();
            bRR = new BeakerResultReporter();
        }
    }

    protected PKITestSuite(Class<?> klass, Class<?>[] suiteClasses)
            throws InitializationError {
        super(klass, suiteClasses);
        String runWithBeaker = System.getenv("RUNNING_WITH_BEAKER");
        if (runWithBeaker != null && runWithBeaker.toLowerCase().equals("true")) {
            run_with_beaker = true;
            beakerScript = BeakerScript.getInstance();
            bRR = new BeakerResultReporter();
        }
    }

    @Override
    protected void runChild(Runner runner, RunNotifier notifier) {
        super.runChild(runner, notifier);
    }

    @Override
    public void run(RunNotifier notifier) {
        if (run_with_beaker)
            notifier.addListener(bRR);
        super.run(notifier);
        if (run_with_beaker)
            writeAndExecuteBeakerCommands();
    }

    private void writeAndExecuteBeakerCommands() {
        File file = new File("java-tests-script.sh");
        PrintWriter pw = null;
        try {
            pw = new PrintWriter(file);
            pw.write(beakerScript.getAllCommandsToRun());
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } finally {
            if (pw != null)
                pw.close();
        }
    }

}

/**
 * Additional run listener to invoke corresponding beaker-lib system call
 * for every JUnit test event.
 * @author akoneru
 *
 */
class BeakerResultReporter extends RunListener {

    private boolean result = true;
    BeakerScript beakerScript;

    public BeakerResultReporter() {
        beakerScript = BeakerScript.getInstance();
    }

    @Override
    public void testRunStarted(Description description) throws Exception {
        beakerScript.addBeakerCommand(new String[] { "rlPhaseStart",
                description.getDisplayName() });
        super.testRunStarted(description);
    }

    @Override
    public void testRunFinished(Result result) throws Exception {
        super.testRunFinished(result);
        beakerScript.addBeakerCommand(new String[] { "rlPhaseEnd" });
    }

    @Override
    public void testAssumptionFailure(Failure failure) {
        super.testAssumptionFailure(failure);
    }

    @Override
    public void testStarted(Description description) throws Exception {
        super.testStarted(description);
        beakerScript.addBeakerCommand(new String[] { "rlPhaseStartTest",
                description.getDisplayName() });
    }

    @Override
    public void testFailure(Failure failure) throws Exception {
        super.testFailure(failure);
        result = false;
        beakerScript.addBeakerCommand(new String[] { "rlFail",
                failure.getMessage() });
    }

    @Override
    public void testFinished(Description description) throws Exception {
        super.testFinished(description);
        if (result) {
            beakerScript
                    .addBeakerCommand(new String[] { "rlPass",
                            description.getDisplayName(),
                            description.getMethodName() });
        }
        beakerScript.addBeakerCommand(new String[] { "rlPhaseEnd" });
    }

    @Override
    public void testIgnored(Description description) throws Exception {
        super.testIgnored(description);
    }

}

/**
 * Represents the beaker script to be executed after the tests are completed.
 * @author akoneru
 *
 */
final class BeakerScript {

    private static BeakerScript beakerScript = new BeakerScript();

    private String beakerLib;
    private StringBuilder commandStore;

    private BeakerScript() {
        // TODO Auto-generated constructor stub
        // Add a check for the availability of beaker lib.
        String bashHeader = "#!/bin/bash";
        beakerLib = ". /usr/share/beakerlib/beakerlib.sh";
        commandStore = new StringBuilder(bashHeader);
        commandStore.append("\n");
        commandStore.append(beakerLib);
        commandStore.append("\n");
    }

    public static BeakerScript getInstance() {
        return beakerScript;
    }

    public void addBeakerCommand(String[] command) {
        for (int i = 0; i < command.length; i++) {
            commandStore.append(command[i]);
            commandStore.append(" ");
            if (i == 0 && command.length > 1) {
                commandStore.append("\"");
            }
        }
        if (command.length > 1)
            commandStore.append("\"");
        commandStore.append("\n");
    }

    public String getAllCommandsToRun() {
        return commandStore.toString();
    }

    public void close() {
        beakerScript = new BeakerScript();
    }
}