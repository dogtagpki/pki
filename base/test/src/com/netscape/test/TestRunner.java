package com.netscape.test;

import java.util.ArrayList;
import java.util.List;

import org.junit.internal.RealSystem;
import org.junit.runner.Description;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

public class TestRunner {

    public Result run(String... args) throws Exception {

        JUnitCore core = new JUnitCore();
        core.addListener(new TestListener());
        RealSystem system = new RealSystem();

        List<Class<?>> classes= new ArrayList<Class<?>>();
        List<Failure> missingClasses= new ArrayList<Failure>();
        for (String each : args) {
              try {
                    classes.add(Class.forName(each));
              } catch (ClassNotFoundException e) {
                    system.out().println("Could not find class: " + each);
                    Description description= Description.createSuiteDescription(each);
                    Failure failure= new Failure(description, e);
                    missingClasses.add(failure);
              }
        }
        Result result= core.run(classes.toArray(new Class[0]));
        for (Failure each : missingClasses)
              result.getFailures().add(each);

        return result;
    }

    public static void main(String... args) throws Exception {

        TestRunner runner = new TestRunner();
        Result result = runner.run(args);
        System.exit(result.wasSuccessful() ? 0 : 1);
    }
}
