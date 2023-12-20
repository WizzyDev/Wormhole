// SPDX-License-Identifier: MIT
pragma solidity >=0.6.12 <0.9.0;

interface IEndpoint {
    function sendMessage(uint16 recipientChain, bytes memory payload) external payable;
    function receiveMessage(bytes memory encodedMessage) external;
    function getEmitters() external view returns (bytes32[] memory);
}