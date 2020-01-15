CREATE TABLE "nonces" (
    "value"            VARCHAR PRIMARY KEY,
    "expires"          TIMESTAMP NOT NULL
);

CREATE TABLE "accounts" (
    "id"               VARCHAR PRIMARY KEY,
    "status"           VARCHAR NOT NULL,
    "jwk"              VARCHAR NOT NULL
);

CREATE TABLE "account_contacts" (
    "account_id"       VARCHAR NOT NULL,
    "contact"          VARCHAR NOT NULL
);

CREATE TABLE "orders" (
    "id"               VARCHAR PRIMARY KEY,
    "account_id"       VARCHAR NOT NULL,
    "status"           VARCHAR NOT NULL,
    "expires"          TIMESTAMP NOT NULL,
    "not_before"       TIMESTAMP,
    "not_after"        TIMESTAMP,
    "csr"              VARCHAR,
    "serial_number"    NUMERIC
);

CREATE TABLE "order_identifiers" (
    "order_id"         VARCHAR NOT NULL,
    "type"             VARCHAR NOT NULL,
    "value"            VARCHAR NOT NULL
);

CREATE TABLE "order_authorizations" (
    "order_id"         VARCHAR NOT NULL,
    "url"              VARCHAR NOT NULL
);

CREATE TABLE "authorizations" (
    "id"               VARCHAR PRIMARY KEY,
    "account_id"       VARCHAR NOT NULL,
    "status"           VARCHAR NOT NULL,
    "expires"          TIMESTAMP NOT NULL,
    "identifier_type"  VARCHAR NOT NULL,
    "identifier_value" VARCHAR NOT NULL,
    "wildcard"         BOOLEAN NOT NULL
);

CREATE TABLE "authorization_challenges" (
    "id"               VARCHAR NOT NULL,
    "authz_id"         VARCHAR NOT NULL,
    "type"             VARCHAR NOT NULL,
    "url"              VARCHAR NOT NULL,
    "token"            VARCHAR NOT NULL,
    "status"           VARCHAR NOT NULL,
    "validated"        TIMESTAMP
);
