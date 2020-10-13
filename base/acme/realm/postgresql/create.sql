CREATE TABLE "users" (
    "id"               VARCHAR PRIMARY KEY,
    "full_name"        VARCHAR,
    "password"         VARCHAR
);

CREATE TABLE "user_certs" (
    "user_id"          VARCHAR NOT NULL,
    "cert_id"          VARCHAR NOT NULL,
    "data"             BYTEA,
    PRIMARY KEY ("user_id", "cert_id")
);

CREATE TABLE "groups" (
    "id"               VARCHAR PRIMARY KEY,
    "description"      VARCHAR
);

CREATE TABLE "group_members" (
    "group_id"         VARCHAR NOT NULL,
    "user_id"          VARCHAR NOT NULL,
    PRIMARY KEY ("group_id", "user_id")
);
