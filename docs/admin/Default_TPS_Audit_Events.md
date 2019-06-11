Default TPS Audit Events
========================

The following audit events are enabled by default in TPS subsystem:

| Event                                       | Filter            |
| ------------------------------------------- | ----------------- |
| ACCESS_SESSION_ESTABLISH                    |                   |
| ACCESS_SESSION_TERMINATED                   |                   |
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
| CONFIG_TOKEN_AUTHENTICATOR                  |                   |
| CONFIG_TOKEN_CONNECTOR                      |                   |
| CONFIG_TOKEN_MAPPING_RESOLVER               |                   |
| CONFIG_TOKEN_RECORD                         |                   |
| CONFIG_TRUSTED_PUBLIC_KEY                   |                   |
| KEY_GEN_ASYMMETRIC                          |                   |
| LOG_PATH_CHANGE                             |                   |
| RANDOM_GENERATION                           | (Outcome=Failure) |
| ROLE_ASSUME                                 |                   |
| SCHEDULE_CRL_GENERATION                     |                   |
| SELFTESTS_EXECUTION                         |                   |
| SERVER_SIDE_KEYGEN_REQUEST                  |                   |
| SERVER_SIDE_KEYGEN_REQUEST_PROCESSED        |                   |
| TOKEN_APPLET_UPGRADE                        | (Outcome=Failure) |
| TOKEN_KEY_CHANGEOVER                        | (Outcome=Failure) |
| TOKEN_KEY_CHANGEOVER_REQUIRED               |                   |

This information can also be obtained with the following command:

```
$ pki-server tps-audit-event-find --enabledByDefault True
```
