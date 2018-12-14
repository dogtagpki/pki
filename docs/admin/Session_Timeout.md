Session Timeout
===============

## Overview

When a user connects to PKI server via a client application, the server will create a session to keep track of the user.
As long as the user remains active, the user can execute multiple operations over the same session without having to re-authenticate.

Session timeout determines how long the server will wait since the last operation before terminating the session due to inactivity.
Once the session is terminated, the user will be required to re-authenticate to continue accessing the server, and the server will create a new session.

There are two types of timeouts:
* TLS session timeout
* HTTP session timeout

Due to differences in the way the clients works, the clients will be affected differently by these timeouts.

### TLS Session Timeout

TLS session is a secure communication channel over a TLS connection established through TLS handshake protocol.

PKI server generates audit events for TLS session activities.
If the connection is successfully created, the server will generate an ACCESS_SESSION_ESTABLISH audit event with Outcome=Success.
If the connection fails to be created, the server will generate an ACCESS_SESSION_ESTABLISH audit event with Outcome=Failure.
When the connection is closed, the server will generate an ACCESS_SESSION_TERMINATED audit event.

TLS session timeout (i.e. TLS connection timeout) can be configured in the **keepAliveTimeout** parameter in the **Secure** &lt;Connector&gt; element in /etc/pki/&lt;instance&gt;/server.xml:

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

Note that this value will affect all TLS connections to the server.
A large value may improve the efficiency of the clients since they can reuse existing connections that have not expired.
However, it may also increase the number of connections that the server has to support simultaneously since it takes longer for abandoned connections to expire.

See also [Tomcat HTTP Connector](https://tomcat.apache.org/tomcat-8.5-doc/config/http.html).

### HTTP Session Timeout

HTTP session is a mechanism to track a user across multiple HTTP requests using HTTP cookies.
PKI server does not generate audit events for HTTP sessions.

HTTP session timeout can be configured in the **&lt;session-timeout&gt;** element in /etc/pki/&lt;instance&gt;/web.xml:

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
A large value may improve the experience of the users since they will not be required to re-authenticate or view the access banner again as often.
However, it may also increase the security risk since it takes longer for abandoned HTTP sessions to expire.

### Session Timeout for PKI Web UI

PKI Web UI is an interactive web-based client that runs in a browser.
Currently it only supports client certificate authentication.

When the Web UI is opened, the browser may create multiple TLS connections to the server.
These connections are associated to a single HTTP session.

To configure a timeout for the Web UI, follow the instruction on configuring HTTP session timeout above.
The TLS session timeout is normally irrelevant since the browser caches the client certificate so it can recreate the TLS session automatically.

When the HTTP session expires, the Web UI will not indicate anything about that immediately.
However, when the user tries to execute another operation, the Web UI will display the access banner (if enabled) before executing the operation.

### Session Timeout for PKI Console

PKI Console is an interactive standalone graphical UI client.
It supports username/password and client certificate authentication.

When the console is started, it will create a single TLS connection to the server.
The console will display the access banner (if enabled) before opening the graphical interface.
Unlike the Web UI, the console does not maintain an HTTP session with the server.

To configure a timeout for the console, follow the instruction on configuring TLS session timeout above.
The HTTP session timeout is irrelevant since the console does not use HTTP session.

When the TLS session expires, the TLS connection will close, and the console will exit immediately to the system.
If the user wants to continue, the user will need to restart the console.

### Session Timeout for PKI CLI

PKI CLI is a command-line client that executes a series of operations. It supports username/password and client certificate authentication.

When the CLI is started, it will create a single TLS connection to the server and an HTTP session.
The CLI will display the access banner (if enabled) before executing the operations.

Both timeouts are generally irrelevant to PKI CLI since the operations are executed in sequence without delay and the CLI exits immediately upon completion.
However, if the CLI waits for user inputs or for some reason is slow or hangs, the TLS session or the HTTP session may expire and the remaining operations may fail.
If such delay is expected, follow the instruction on configuring the TLS session timeout and HTTP session timeout above to accommodate the expected delay.
