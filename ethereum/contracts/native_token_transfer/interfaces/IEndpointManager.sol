// SPDX-License-Identifier: MIT
pragma solidity >=0.6.12 <0.9.0;

interface IEndpointManager {
    function transfer(uint256 amount, uint16 recipientChain, bytes32 recipient) external payable returns (uint64 msgId);
    function attestationReceived(bytes memory payload) external;
    function getThreshold() external view returns (uint8);
    function getEndpoints() external view returns (address[] memory);
    function nextSequence() external view returns (uint64);
}