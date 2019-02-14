Default OCSP Audit Events
=========================

The following audit events are enabled by default in OCSP subsystem:

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
| CONFIG_OCSP_PROFILE                         |                   |
| CONFIG_ROLE                                 |                   |
| CONFIG_SIGNED_AUDIT                         |                   |
| CONFIG_TRUSTED_PUBLIC_KEY                   |                   |
| KEY_GEN_ASYMMETRIC                          |                   |
| LOG_PATH_CHANGE                             |                   |
| OCSP_ADD_CA_REQUEST_PROCESSED               |                   |
| OCSP_GENERATION                             |                   |
| OCSP_REMOVE_CA_REQUEST_PROCESSED            |                   |
| OCSP_SIGNING_INFO                           |                   |
| RANDOM_GENERATION                           | (Outcome=Failure) |
| ROLE_ASSUME                                 |                   |
| SCHEDULE_CRL_GENERATION                     |                   |
| SELFTESTS_EXECUTION                         |                   |
| SERVER_SIDE_KEYGEN_REQUEST                  |                   |
| SERVER_SIDE_KEYGEN_REQUEST_PROCESSED        |                   |

This information can also be obtained with the following command:

```
$ pki-server ocsp-audit-event-find --enabledByDefault True
```
