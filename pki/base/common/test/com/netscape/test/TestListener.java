package com.netscape.test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintStream;
import java.net.InetAddress;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.junit.runner.Description;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;
import org.junit.runner.notification.RunListener;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

public class TestListener extends RunListener {

    DateFormat dateFormat;

    DocumentBuilderFactory docBuilderFactory;
    DocumentBuilder docBuilder;
    Document document;

    TransformerFactory transFactory;
    Transformer trans;

    String reportsDir;

    Element testSuiteElement;
    long testSuiteStartTime;

    Element testCaseElement;
    long testCaseStartTime;

    String currentTestSuiteName;

    long testCount;
    long successCount;
    long failureCount;

    PrintStream stdOut;
    PrintStream stdErr;

    ByteArrayOutputStream out;
    ByteArrayOutputStream err;

    public TestListener() throws Exception {

        dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));

        docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilder = docBuilderFactory.newDocumentBuilder();

        transFactory = TransformerFactory.newInstance();
        trans = transFactory.newTransformer();
        trans.setOutputProperty(OutputKeys.INDENT, "yes");

        reportsDir = System.getProperty("junit.reports.dir");
    }

    public void testRunFinished(Result result) throws Exception {
        if (currentTestSuiteName != null) {
            finishTestSuite(); // finish last suite
        }
    }

    public void testStarted(Description description) throws Exception {

        String testSuiteName = description.getClassName();

        if (currentTestSuiteName == null) {
            startTestSuite(testSuiteName); // start first suite

        } else if (!currentTestSuiteName.equals(testSuiteName)) {
            finishTestSuite(); // finish old suite
            startTestSuite(testSuiteName); // start new suite
        }

        currentTestSuiteName = testSuiteName;

        startTestCase(description);
    }

    public void testFinished(Description description) throws Exception {
        finishTestCase();
        recordTestCaseSuccess();
    }

    public void testFailure(Failure failure) throws Exception {
        finishTestCase();
        recordTestCaseFailure(failure);
    }

    public void startTestSuite(String testSuiteName) throws Exception {

        testSuiteStartTime = System.currentTimeMillis();

        document = docBuilder.newDocument();

        // test suite
        testSuiteElement = document.createElement("testsuite");
        document.appendChild(testSuiteElement);

        testSuiteElement.setAttribute("name", testSuiteName);
        testSuiteElement.setAttribute("timestamp",
                dateFormat.format(new Date(testSuiteStartTime)));
        testSuiteElement.setAttribute("hostname", InetAddress.getLocalHost()
                .getHostName());

        // system properties
        Element propertiesElement = document.createElement("properties");
        testSuiteElement.appendChild(propertiesElement);

        for (String name : System.getProperties().stringPropertyNames()) {
            Element propertyElement = document.createElement("property");
            propertyElement.setAttribute("name", name);
            propertyElement.setAttribute("value", System.getProperty(name));
            propertiesElement.appendChild(propertyElement);
        }

        // reset counters
        testCount = 0;
        successCount = 0;
        failureCount = 0;

        // redirect outputs
        stdOut = System.out;
        out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true));

        stdErr = System.err;
        err = new ByteArrayOutputStream();
        System.setErr(new PrintStream(err, true));
    }

    public void finishTestSuite() throws Exception {

        double time = (System.currentTimeMillis() - testSuiteStartTime) / 1000.0;
        testSuiteElement.setAttribute("time", "" + time);

        // save counters
        long errorCount = testCount - successCount - failureCount;

        testSuiteElement.setAttribute("tests", "" + testCount);
        testSuiteElement.setAttribute("failures", "" + failureCount);
        testSuiteElement.setAttribute("errors", "" + errorCount);

        // save outputs
        System.setOut(stdOut);
        System.setErr(stdErr);

        Element systemOutElement = document.createElement("system-out");
        testSuiteElement.appendChild(systemOutElement);

        systemOutElement
                .appendChild(document.createCDATASection(out.toString()));

        Element systemErrElement = document.createElement("system-err");
        testSuiteElement.appendChild(systemErrElement);

        systemErrElement
                .appendChild(document.createCDATASection(err.toString()));

        // write to file
        FileWriter fw = new FileWriter(reportsDir + File.separator + "TEST-"
                + currentTestSuiteName + ".xml");
        StreamResult sr = new StreamResult(fw);
        DOMSource source = new DOMSource(document);
        trans.transform(source, sr);
        fw.close();
    }

    public void startTestCase(Description description) throws Exception {

        testCaseStartTime = System.currentTimeMillis();

        testCaseElement = document.createElement("testcase");
        testSuiteElement.appendChild(testCaseElement);

        testCaseElement.setAttribute("classname", description.getClassName());
        testCaseElement.setAttribute("name", description.getMethodName());

        testCount++;
    }

    public void finishTestCase() throws Exception {
        double time = (System.currentTimeMillis() - testCaseStartTime) / 1000.0;
        testCaseElement.setAttribute("time", "" + time);
    }

    public void recordTestCaseSuccess() throws Exception {
        successCount++;
    }

    public void recordTestCaseFailure(Failure failure) throws Exception {

        Element failureElement = document.createElement("failure");
        testCaseElement.appendChild(failureElement);

        Description description = failure.getDescription();
        Throwable exception = failure.getException();
        String exceptionName = exception.getClass().getName();

        failureElement.setAttribute("message", failure.getMessage());
        failureElement.setAttribute("type", exceptionName);

        Text messageElement = document.createTextNode(exceptionName + ": "
                + failure.getMessage() + "\n");

        // print stack trace
        for (StackTraceElement element : exception.getStackTrace()) {
            if (!element.getClassName().equals(description.getClassName()))
                continue;

            String source = "Unknown Source";
            if (element.getFileName() != null && element.getLineNumber() >= 0) {
                source = element.getFileName() + ":" + element.getLineNumber();
            }

            messageElement.appendData("\tat " + element.getClassName() + "."
                    + element.getMethodName() + "(" + source + ")\n");
        }

        failureElement.appendChild(messageElement);

        failureCount++;
    }
}
