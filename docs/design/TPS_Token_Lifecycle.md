# TPS Token Lifecycle

## Overview

Tokens in TPS may exist in one of the following states:

* UNFORMATTED: Unformatted
* FORMATTED: Formatted (uninitialized)
* ACTIVE: Active
* SUSPENDED: Suspended (temporarily lost)
* TERMINATED: Terminated
* DAMAGED: Physically damaged
* PERM_LOST: Permanently lost

The state determines what actions that can be taken on the token.
The action may also bring the token into another state.

## Token Activation

![TPS Token Activation](images/TPS_Token_Activation.svg)

A new token can be added into TPS in unformatted/blank state via TPS CLI or Web UI.
The token then can be activated via TPS token operations.
The format operation will install the Coolkey applet onto the token.
The enrollment operation will install the certificates and keys.

## Token Suspension

![TPS Token Suspension](images/TPS_Token_Suspension.svg)

A formatted or active token can be suspended via TPS CLI or Web UI to temporarily prevent its use.
When it is restored, it will return to its previous formatted/active state.

## Token Termination

![TPS Token Termination](images/TPS_Token_Termination.svg)

When the token is no longer needed it can be terminated via TPS CLI or Web UI.
Terminated token can later be reused as a new token.

## Token Damaged

![TPS Token Damaged](images/TPS_Token_Damaged.svg)

A token can be marked damaged via TPS CLI or Web UI.
A damaged token can no longer be used in TPS.

## Token Lost

![TPS Token Lost](images/TPS_Token_Lost.svg)

A token can be marked lost via TPS CLI or Web UI.
A lost token can no longer be used in TPS.
