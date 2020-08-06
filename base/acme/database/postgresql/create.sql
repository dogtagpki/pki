CREATE TABLE "nonces" (
    "id"               VARCHAR PRIMARY KEY,
    "created"          TIMESTAMPTZ NOT NULL,
    "expires"          TIMESTAMPTZ NOT NULL
);

CREATE TABLE "accounts" (
    "id"               VARCHAR PRIMARY KEY,
    "created"          TIMESTAMPTZ NOT NULL,
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
    "created"          TIMESTAMPTZ NOT NULL,
    "status"           VARCHAR NOT NULL,
    "expires"          TIMESTAMPTZ,
    "not_before"       TIMESTAMPTZ,
    "not_after"        TIMESTAMPTZ,
    "cert_id"          VARCHAR
);

CREATE TABLE "order_identifiers" (
    "order_id"         VARCHAR NOT NULL,
    "type"             VARCHAR NOT NULL,
    "value"            VARCHAR NOT NULL
);

CREATE TABLE "order_authorizations" (
    "order_id"         VARCHAR NOT NULL,
    "authz_id"         VARCHAR NOT NULL
);

CREATE TABLE "authorizations" (
    "id"               VARCHAR PRIMARY KEY,
    "account_id"       VARCHAR NOT NULL,
    "created"          TIMESTAMPTZ NOT NULL,
    "status"           VARCHAR NOT NULL,
    "expires"          TIMESTAMPTZ,
    "identifier_type"  VARCHAR NOT NULL,
    "identifier_value" VARCHAR NOT NULL,
    "wildcard"         BOOLEAN NOT NULL
);

CREATE TABLE "authorization_challenges" (
    "id"               VARCHAR NOT NULL,
    "authz_id"         VARCHAR NOT NULL,
    "type"             VARCHAR NOT NULL,
    "token"            VARCHAR NOT NULL,
    "status"           VARCHAR NOT NULL,
    "validated"        TIMESTAMPTZ
);

CREATE TABLE "certificates" (
    "id"               VARCHAR PRIMARY KEY,
    "created"          TIMESTAMPTZ NOT NULL,
    "data"             BYTEA,
    "expires"          TIMESTAMPTZ
);
