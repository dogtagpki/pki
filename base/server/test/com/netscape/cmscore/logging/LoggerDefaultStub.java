package com.netscape.cmscore.logging;

import com.netscape.certsrv.logging.ILogEvent;
import com.netscape.certsrv.logging.ILogQueue;
import com.netscape.certsrv.logging.ILogger;
import com.netscape.certsrv.logging.LogCategory;
import com.netscape.certsrv.logging.LogSource;

/**
 * Default logging stub for testing.
 */
public class LoggerDefaultStub implements ILogger {
    public void log(LogCategory evtClass, LogSource source, String msg) {
    }

    public void log(LogCategory evtClass, LogSource source, int level, String msg) {
    }

    public void log(LogCategory evtClass, LogSource source, int level, String msg, Object param) {
    }

    public void log(LogCategory evtClass, LogSource source, int level, String msg, Object params[]) {
    }

    public void log(LogCategory evtClass, LogSource source, String msg, boolean multiline) {
    }

    public void log(LogCategory evtClass, LogSource source, int level, String msg, boolean multiline) {
    }

    public void log(LogCategory evtClass, LogSource source, int level, String msg, Object param, boolean multiline) {
    }

    public ILogEvent create(LogCategory evtClass, LogSource source, int level, String msg, Object params[],
            boolean multiline) {
        return null;
    }

    public ILogQueue getLogQueue() {
        return null;
    }
}
