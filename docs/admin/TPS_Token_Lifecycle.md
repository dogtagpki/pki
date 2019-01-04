# TPS Token Lifecycle

## Token States

Below are the supported token states in TPS:

| Code | Name        | Label                        |
| ---- | ----------- | ---------------------------- |
| 0    | FORMATTED   | Formatted (uninitialized)    |
| 1    | DAMAGED     | Physically damaged           |
| 2    | PERM_LOST   | Permanently lost             |
| 3    | SUSPENDED   | Suspended (temporarily lost) |
| 4    | ACTIVE      | Active                       |
| 6    | TERMINATED  | Terminated                   |
| 7    | UNFORMATTED | Unformatted                  |

In the CS.cfg the token states will be displayed by their codes.
In PKI CLI the token states will be displayed by their names.
In TPS Web UI the token states will be displayed by their labels.

## Token State Transitions via PKI CLI or TPS Web UI

Token state can be changed via PKI CLI or TPS Web UI.
The transitions that can be done via PKI CLI or TPS Web UI are defined in the following property in
/etc/pki/&lt;instance&gt;/tps/CS.cfg:

```
tokendb.allowedTransitions=0:1,0:2,0:3,0:6,3:2,3:6,4:1,4:2,4:3,4:6,6:7
```

The property contains a comma-separated list of transitions. Each transition is written in this format:

    <current state code>:<new state code>

The above list represents the following transitions:

| Transition | Current State | Next State  | Label                                                          |
| ---------- | ------------- | ----------- | -------------------------------------------------------------- |
| 0:1        | FORMATTED     | DAMAGED     | This token has been physically damaged.                        |
| 0:2        | FORMATTED     | PERM_LOST   | This token has been permanently lost.                          |
| 0:3        | FORMATTED     | SUSPENDED   | This token has been suspended (temporarily lost).              |
| 0:6        | FORMATTED     | TERMINATED  | This token has been terminated.                                |
| 3:2        | SUSPENDED     | TERMINATED  | This suspended (temporarily lost) token has been terminated.   |
| 3:6        | SUSPENDED     | PERM_LOST   | This suspended (temporarily lost) has become permanently lost. |
| 4:1        | ACTIVE        | DAMAGED     | This token has been physically damaged.                        |
| 4:2        | ACTIVE        | PERM_LOST   | This token has been permanently lost.                          |
| 4:3        | ACTIVE        | SUSPENDED   | This token has been suspended (temporarily lost).              |
| 4:6        | ACTIVE        | TERMINATED  | This token has been terminated.                                |
| 6:7        | TERMINATED    | UNFORMATTED | Reuse this token.                                              |

The following transitions are generated automatically depending on the original state of the token.
If a token was originally FORMATTED then became SUSPENDED, it can only return to FORMATTED state.
If a token was originally ACTIVE then became SUSPENDED, it can only return to the ACTIVE state.

| Transition | Current State | Next State | Label                                                   |
| ---------- | ------------- | ---------- | ------------------------------------------------------- |
| 3:2        | SUSPENDED     | FORMATTED  | This suspended (temporarily lost) token has been found. |
| 3:4        | SUSPENDED     | ACTIVE     | This suspended (temporarily lost) token has been found. |

To customize the tokendb.allowedTransitions property, edit the property in /etc/pki/&lt;instance&gt;/tps/CS.cfg,
then restart the server.

## Token State Transitions via Token Operations

Token states can also be changed via token operations (e.g. format, enroll).
The transitions that can be done via token operations are defined in the following property in
/etc/pki/&lt;instance&gt;/tps/CS.cfg:

```
tps.operations.allowedTransitions=0:0,0:4,4:4,4:0,7:0
```

The property contains a comma-delimited list of transitions.
Each transition is written in this format:

    <current state code>:<new state code>

The above list represents the following transitions:

| Transition | Current State | Next State | Description                                                           |
| ---------- | ------------- | ---------- | --------------------------------------------------------------------- |
| 0:0        | FORMATTED     | FORMATTED  | This allows reformatting a token or upgrading applet/key in a token.  |
| 0:4        | FORMATTED     | ACTIVE     | This allows enrolling a token.                                        |
| 4:4        | ACTIVE        | ACTIVE     | This allows re-enrolling an active token (for external registration). |
| 4:0        | ACTIVE        | FORMATTED  | This allows formatting an active token.                               |
| 7:0        | UNFORMATTED   | FORMATTED  | This allows formatting a blank or previously used token.              |

To customize the tps.operations.allowedTransitions property, edit the property in /etc/pki/&lt;instance&gt;/tps/CS.cfg,
then restart the server.

This property can only be customized to remove transitions from the original list.
New transitions cannot be added into tps.operations.allowedTransitions unless it is already defined
in the default tps.operations.allowedTransitions in /usr/share/pki/tps/conf/CS.cfg.

## Token State and Transition Labels for TPS Web UI

The default token state and transition labels for TPS Web UI are defined in /usr/share/pki/tps/conf/token-states.properties:

```
# Token states
UNFORMATTED         = Unformatted
FORMATTED           = Formatted (uninitialized)
ACTIVE              = Active
SUSPENDED           = Suspended (temporarily lost)
PERM_LOST           = Permanently lost
DAMAGED             = Physically damaged
TEMP_LOST_PERM_LOST = Temporarily lost then permanently lost
TERMINATED          = Terminated

# Token state transitions
FORMATTED.DAMAGED        = This token has been physically damaged.
FORMATTED.PERM_LOST      = This token has been permanently lost.
FORMATTED.SUSPENDED      = This token has been suspended (temporarily lost).
FORMATTED.TERMINATED     = This token has been terminated.
SUSPENDED.ACTIVE         = This suspended (temporarily lost) token has been found.
SUSPENDED.PERM_LOST      = This suspended (temporarily lost) token has become permanently lost.
SUSPENDED.TERMINATED     = This suspended (temporarily lost) token has been terminated.
SUSPENDED.FORMATTED      = This suspended (temporarily lost) token has been found.
ACTIVE.DAMAGED           = This token has been physically damaged.
ACTIVE.PERM_LOST         = This token has been permanently lost.
ACTIVE.SUSPENDED         = This token has been suspended (temporarily lost).
ACTIVE.TERMINATED        = This token has been terminated.
TERMINATED.UNFORMATTED   = Reuse this token.
```

To customize the labels, copy the default token-states.properties into TPS configuration folder:

```
$ cp /usr/share/pki/tps/conf/token-states.properties /var/lib/pki/pki-tomcat/tps/conf
```
Then edit the new file.
There is no need to restart the server, but the TPS Web UI will need to be reloaded.

To remove the customized labels simply delete the customized file:

```
$ rm /var/lib/pki/pki-tomcat/tps/conf/token-states.properties
```
Then reload the TPS Web UI.
