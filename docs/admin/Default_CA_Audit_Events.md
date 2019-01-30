Default CA Audit Events
=======================

The following audit events are enabled by default in CA subsystem:

| Event                                       | Filter            |
| ------------------------------------------- | ----------------- |
| ACCESS_SESSION_ESTABLISH                    |                   |
| ACCESS_SESSION_TERMINATED                   |                   |
| AUDIT_LOG_SHUTDOWN                          |                   |
| AUDIT_LOG_SIGNING                           |                   |
| AUDIT_LOG_STARTUP                           |                   |
| AUTH                                        |                   |
| AUTHORITY_CONFIG                            |                   |
| AUTHZ                                       |                   |
| CERT_PROFILE_APPROVAL                       |                   |
| CERT_REQUEST_PROCESSED                      |                   |
| CERT_SIGNING_INFO                           |                   |
| CERT_STATUS_CHANGE_REQUEST                  |                   |
| CERT_STATUS_CHANGE_REQUEST_PROCESSED        |                   |
| CLIENT_ACCESS_SESSION_ESTABLISH             |                   |
| CLIENT_ACCESS_SESSION_TERMINATED            |                   |
| CMC_REQUEST_RECEIVED                        |                   |
| CMC_RESPONSE_SENT                           |                   |
| CMC_SIGNED_REQUEST_SIG_VERIFY               | (Outcome=Failure) |
| CMC_USER_SIGNED_REQUEST_SIG_VERIFY          | (Outcome=Failure) |
| CONFIG_ACL                                  |                   |
| CONFIG_AUTH                                 |                   |
| CONFIG_CERT_PROFILE                         |                   |
| CONFIG_CRL_PROFILE                          |                   |
| CONFIG_ENCRYPTION                           |                   |
| CONFIG_ROLE                                 |                   |
| CONFIG_SERIAL_NUMBER                        |                   |
| CONFIG_SIGNED_AUDIT                         |                   |
| CONFIG_TRUSTED_PUBLIC_KEY                   |                   |
| CRL_SIGNING_INFO                            |                   |
| DELTA_CRL_GENERATION                        | (Outcome=Failure) |
| FULL_CRL_GENERATION                         | (Outcome=Failure) |
| KEY_GEN_ASYMMETRIC                          |                   |
| LOG_PATH_CHANGE                             |                   |
| OCSP_GENERATION                             | (Outcome=Failure) |
| OCSP_SIGNING_INFO                           |                   |
| PROFILE_CERT_REQUEST                        |                   |
| PROOF_OF_POSSESSION                         |                   |
| RANDOM_GENERATION                           | (Outcome=Failure) |
| ROLE_ASSUME                                 |                   |
| SECURITY_DATA_ARCHIVAL_REQUEST              |                   |
| SECURITY_DOMAIN_UPDATE                      |                   |
| SELFTESTS_EXECUTION                         |                   |
| SERVER_SIDE_KEYGEN_REQUEST                  |                   |
| SERVER_SIDE_KEYGEN_REQUEST_PROCESSED        |                   |

This information can also be obtained with the following command:

```
$ pki-server ca-audit-event-find --enabledByDefault True
```
