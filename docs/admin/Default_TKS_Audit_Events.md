Default TKS Audit Events
========================

The following audit events are enabled by default in TKS subsystem:

| Event                                       | Filter            |
| ------------------------------------------- | ----------------- |
| ACCESS_SESSION_ESTABLISH                    |                   |
| ACCESS_SESSION_TERMINATED                   |                   |
| AUDIT_LOG_SHUTDOWN                          |                   |
| AUDIT_LOG_SIGNING                           |                   |
| AUDIT_LOG_STARTUP                           |                   |
| AUTH                                        |                   |
| AUTHZ                                       |                   |
| CLIENT_ACCESS_SESSION_ESTABLISH             |                   |
| CLIENT_ACCESS_SESSION_TERMINATED            |                   |
| CONFIG_ACL                                  |                   |
| CONFIG_AUTH                                 |                   |
| CONFIG_ENCRYPTION                           |                   |
| CONFIG_ROLE                                 |                   |
| CONFIG_SIGNED_AUDIT                         |                   |
| CONFIG_TRUSTED_PUBLIC_KEY                   |                   |
| KEY_GEN_ASYMMETRIC                          |                   |
| LOG_PATH_CHANGE                             |                   |
| RANDOM_GENERATION                           | (Outcome=Failure) |
| ROLE_ASSUME                                 |                   |
| SELFTESTS_EXECUTION                         |                   |
| SERVER_SIDE_KEYGEN_REQUEST                  |                   |
| SERVER_SIDE_KEYGEN_REQUEST_PROCESSED        |                   |

This information can also be obtained with the following command:

```
$ pki-server tks-audit-event-find --enabledByDefault True
```
