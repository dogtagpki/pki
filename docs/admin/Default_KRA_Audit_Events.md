Default KRA Audit Events
========================

The following audit events are enabled by default in KRA subsystem:

| Event                                       | Filter            |
| ------------------------------------------- | ----------------- |
| ACCESS_SESSION_ESTABLISH                    |                   |
| ACCESS_SESSION_TERMINATED                   |                   |
| ASYMKEY_GENERATION_REQUEST                  | (Outcome=Failure) |
| ASYMKEY_GENERATION_REQUEST_PROCESSED        | (Outcome=Failure) |
| AUDIT_LOG_SHUTDOWN                          |                   |
| AUDIT_LOG_SIGNING                           |                   |
| AUDIT_LOG_STARTUP                           |                   |
| AUTH                                        |                   |
| AUTHZ                                       |                   |
| CLIENT_ACCESS_SESSION_ESTABLISH             |                   |
| CLIENT_ACCESS_SESSION_TERMINATED            |                   |
| CONFIG_ACL                                  |                   |
| CONFIG_AUTH                                 |                   |
| CONFIG_DRM                                  |                   |
| CONFIG_ENCRYPTION                           |                   |
| CONFIG_ROLE                                 |                   |
| CONFIG_SERIAL_NUMBER                        |                   |
| CONFIG_SIGNED_AUDIT                         |                   |
| CONFIG_TRUSTED_PUBLIC_KEY                   |                   |
| KEY_GEN_ASYMMETRIC                          |                   |
| LOG_PATH_CHANGE                             |                   |
| RANDOM_GENERATION                           | (Outcome=Failure) |
| ROLE_ASSUME                                 |                   |
| SECURITY_DATA_ARCHIVAL_REQUEST              | (Outcome=Failure) |
| SECURITY_DATA_ARCHIVAL_REQUEST_PROCESSED    | (Outcome=Failure) |
| SECURITY_DATA_RECOVERY_REQUEST              | (Outcome=Failure) |
| SECURITY_DATA_RECOVERY_REQUEST_PROCESSED    | (Outcome=Failure) |
| SECURITY_DATA_RECOVERY_REQUEST_STATE_CHANGE | (Outcome=Failure) |
| SELFTESTS_EXECUTION                         |                   |
| SERVER_SIDE_KEYGEN_REQUEST                  | (Outcome=Failure) |
| SERVER_SIDE_KEYGEN_REQUEST_PROCESSED        | (Outcome=Failure) |
| SYMKEY_GENERATION_REQUEST                   | (Outcome=Failure) |
| SYMKEY_GENERATION_REQUEST_PROCESSED         | (Outcome=Failure) |

This information can also be obtained with the following command:

```
$ pki-server kra-audit-event-find --enabledByDefault True
```
