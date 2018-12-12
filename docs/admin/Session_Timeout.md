Session Timeout
===============

## Overview

When a user connects to PKI server via a client application, the server will create a session to keep track of the user.
As long as the user remains active, the user can execute multiple operations over the same session without having to re-authenticate.

Session timeout determines how long the server will wait since the last operation before terminating the session due to inactivity.
Once the session is terminated, the user will be required to re-authenticate to continue accessing the server, and the server will create a new session.

Due to differences in the way some clients work, there are several ways to configure the session timeout.

### Session Timeout for PKI Web UI

PKI Web UI is a web-based client that runs in a browser.
When the Web UI is opened, the browser may use multiple connections to communicate with the server.
These connections are associated to the same session using cookies.
If access banner is enabled, the Web UI will display it when the new session is created.

If the session times out, the Web UI can only detect that when the user tries to execute another operation.
When that happens the browser will automatically re-authenticate the user, and the server will create a new session.
If access banner is enabled, it will be displayed again.

The session timeout for PKI Web UI can be configured in the **&lt;session-timeout&gt;** element in /etc/pki/&lt;instance&gt;/web.xml:

<pre>
&lt;web-app&gt;

   &lt;session-config&gt;
        &lt;session-timeout&gt;30&lt;/session-timeout&gt;
   &lt;/session-config&gt;

&lt;/web-app&gt;
</pre>

By default the value is set to 30 minutes.
To change the value, edit the web.xml then restart the server.
Note that this value affects all sessions in all web applications on the server.

### Session Timeout for PKI Console

PKI Console is a standalone graphical UI client.
When the console is started, it will create a single connection to the server and keep it alive as long as the console is running.
If access banner is enabled, it will be displayed to the user during console startup.

Unlike the Web UI, the console does not use cookies to maintain a session on the server.
If the connection is terminated by the server, the console will exit immediately to the system.
If the user wants to continue, the user will need to restart the console.

Because of the way it works, the connection itself acts as a session.
So the session timeout for PKI Console needs to be configured with the **keepAliveTimeout** parameter
in the **Secure** &lt;Connector&gt; element in /etc/pki/&lt;instance&gt;/server.xml:

<pre>
&lt;Server&gt;
    &lt;Service&gt;

        &lt;Connector name="Secure"
            ...
            keepAliveTimeout="300000"
            ...
            /&gt;

    &lt;/Service&gt;
&lt;/Server&gt;
</pre>

By default the value is set to 300000 milliseconds (i.e. 5 minutes).
To change this value, edit the server.xml then restart the server.
Note that this value affects all connections to the server.

See also [Tomcat HTTP Connector](https://tomcat.apache.org/tomcat-8.5-doc/config/http.html).

### Session Timeout for PKI CLI

PKI CLI is a command-line client which executes a set of operations, then exits immediately to the system.
If access banner is enabled, it will be displayed at the beginning of each CLI execution.

Session timeout is generally irrelevant to PKI CLI since the operations are executed in sequence without delay.
However, if the CLI waits for user inputs or for some reason hangs, the session may time out and the remaining operations may fail.
If such delay is expected, the web.xml and server.xml should be configured to accommodate that delay.
