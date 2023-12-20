// SPDX-License-Identifier: MIT
pragma solidity >=0.6.12 <0.9.0;

error SequenceAttestationAlreadyReceived(uint64 sequence, address endpoint);
error UnexpectedEndpointManagerMessageType(uint8 msgType);