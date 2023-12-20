// SPDX-License-Identifier: MIT
pragma solidity >=0.6.12 <0.9.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

import "../libraries/external/BytesLib.sol";
import "./libraries/Errors.sol";
import "./libraries/EndpointStructs.sol";
import "./interfaces/IEndpointManager.sol";
import "./interfaces/IEndpoint.sol";
import "./interfaces/IEndpointToken.sol";

abstract contract EndpointManager is IEndpointManager {
    using BytesLib for bytes;

	address token;
	bool isLockingMode;

	uint64 sequence;
    uint8 threshold;
	mapping(address => bool) public isEndpoint;
	address[] endpoints;
	mapping(uint64 => mapping(address => bool)) public sequenceAttestations;
	mapping(uint64 => uint8) public sequenceAttestationCounts;

	modifier onlyEndpoint() {
		require(isEndpoint[msg.sender], "Caller is not a registered Endpoint");
		_;
	}

	/// @notice Called by the user to send the token cross-chain.
	///         This function will either lock or burn the sender's tokens.
	///         Finally, this function will call into the Endpoint contracts to send a message with the incrementing sequence number, msgType = 1y, and the token transfer payload.
	function transfer(uint256 amount, uint16 recipientChain, bytes32 recipient) external payable returns (uint64 msgSequence) {
		// TODO -- query Endpoint fee handlers to ensure user's msg.value is high enough
		// pass recipient chain to the fee handler.

		// query tokens decimals
        (,bytes memory queriedDecimals) = token.staticcall(abi.encodeWithSignature("decimals()"));
        uint8 decimals = abi.decode(queriedDecimals, (uint8));

        // don't deposit dust that can not be bridged due to the decimal shift
        amount = deNormalizeAmount(normalizeAmount(amount, decimals), decimals);
		
		// use transferFrom to pull tokens from the user and lock them
		// query own token balance before transfer
		(,bytes memory queriedBalanceBefore) = token.staticcall(abi.encodeWithSelector(IERC20.balanceOf.selector, address(this)));
		uint256 balanceBefore = abi.decode(queriedBalanceBefore, (uint256));

		if (isLockingMode) {
            // transfer tokens
            SafeERC20.safeTransferFrom(IERC20(token), msg.sender, address(this), amount);
		} else {
			// call the token's burn function to burn the sender's token
			ERC20Burnable(token).burnFrom(msg.sender, amount);
		}

		// query own token balance after transfer/burn
		(,bytes memory queriedBalanceAfter) = token.staticcall(abi.encodeWithSelector(IERC20.balanceOf.selector, address(this)));
		uint256 balanceAfter = abi.decode(queriedBalanceAfter, (uint256));

		// correct amount for potential transfer/burn fees
		amount = balanceAfter - balanceBefore;

		// normalize amount decimals
        uint256 normalizedAmount = normalizeAmount(amount, decimals);

		// construct the NativeTokenTransfer payload
		NativeTokenTransfer memory transferPayload = NativeTokenTransfer({
			amount: normalizedAmount,
			tokenAddress: bytes32(uint256(uint160(token))),
			to: recipient,
			toChain: recipientChain
		});
		bytes memory encodedTransferPayload = abi.encodePacked(
            transferPayload.amount,
            transferPayload.tokenAddress,
            transferPayload.to,
            transferPayload.toChain
        );

		// construct the ManagerMessage payload
		sequence = useSequence();
		EndpointManagerMessage memory managerPayload = EndpointManagerMessage({
			sequence: sequence,
			msgType: 1,
			payload: encodedTransferPayload
		});
		bytes memory encodedManagerPayload = abi.encodePacked(
			managerPayload.sequence,
			managerPayload.msgType,
			managerPayload.payload
		);

		// call into endpoint contracts to send the message
		for (uint256 i = 0; i < endpoints.length; i++) {
			IEndpoint(endpoints[i]).sendMessage{ value: msg.value }(recipientChain, encodedManagerPayload);
		}

		// return the sequence number
		return sequence;
	}

    function normalizeAmount(uint256 amount, uint8 decimals) internal pure returns(uint256){
        if (decimals > 8) {
            amount /= 10 ** (decimals - 8);
        }
        return amount;
    }

    function deNormalizeAmount(uint256 amount, uint8 decimals) internal pure returns(uint256){
        if (decimals > 8) {
            amount *= 10 ** (decimals - 8);
        }
        return amount;
    }

	/// @notice Called by a Endpoint contract to deliver a verified attestation.
	///         This function will decode the payload as an EndpointManagerMessage to extract the sequence, msgType, and other parameters.
	///         When the threshold is reached for a sequence, this function will execute logic to handle the action specified by the msgType and payload.
	function attestationReceived(bytes memory payload) external onlyEndpoint {
		// parse the payload as an EndpointManagerMessage
		EndpointManagerMessage memory message = parseEndpointManagerMessage(payload);

		// if the attestation for this sender has already been received, revert
		if (sequenceAttestations[message.sequence][msg.sender] == true) {
			revert SequenceAttestationAlreadyReceived(message.sequence, msg.sender);
		}

		// add the Endpoint attestation for the sequence number
		sequenceAttestations[message.sequence][msg.sender] = true;

		// increment the attestations for the sequence
		sequenceAttestationCounts[message.sequence]++;

		// end early if the threshold hasn't been met.
		// otherwise, continue with execution for the message type.
		if (sequenceAttestationCounts[message.sequence] < threshold) {
			return;
		}

		// for msgType == 1, parse the payload as a NativeTokenTransfer.
		// for other msgTypes, revert (unsupported for now)
		if (message.msgType != 1) {
			revert UnexpectedEndpointManagerMessageType(message.msgType);
		}
		NativeTokenTransfer memory nativeTokenTransfer = parseNativeTokenTransfer(message.payload);
		
		// mint tokens to the specified recipient
		address transferRecipient = _truncateAddress(nativeTokenTransfer.to);
		IEndpointToken(token).mint(transferRecipient, nativeTokenTransfer.amount);
	}

	/// @notice Returns the number of Endpoints that must attest to a msgId for it to be considered valid and acted upon.
	function getThreshold() external view returns (uint8) {
		return threshold;
	}

	/// @notice Returns the Endpoint contracts that have been registered via governance.
	function getEndpoints() external view returns (address[] memory) {
		return endpoints;
	}

	function nextSequence() public view returns (uint64) {
        return sequence;
    }

    function useSequence() internal returns (uint64 currentSequence) {
        currentSequence = nextSequence();
        incrementSequence();
    }

	function incrementSequence() internal {
        sequence++;
    }

	function setThreshold(uint8 newThreshold) internal {
		threshold = newThreshold;
	}

	function setEndpoint(address endpoint) internal {
		require(endpoint != address(0), "Invalid endpoint address");
		require(!isEndpoint[endpoint], "This address is already a endpoint");
		isEndpoint[endpoint] = true;	
		endpoints.push(endpoint);
		/// TODO -- emit an event here?
	}

	/*
     * @dev Parse a EndpointManagerMessage.
     *
     * @params encoded The byte array corresponding to the encoded message
     */
    function parseEndpointManagerMessage(bytes memory encoded)
		public
		pure
		returns (EndpointManagerMessage memory managerMessage)
	{
        uint256 index = 0;

		managerMessage.sequence = encoded.toUint64(index);
		index += 8;

		managerMessage.msgType = encoded.toUint8(index);
		index += 1;

		managerMessage.payload = encoded.slice(index, encoded.length - index);
    }

	/*
     * @dev Parse a NativeTokenTransfer.
     *
     * @params encoded The byte array corresponding to the encoded message
     */
	function parseNativeTokenTransfer(bytes memory encoded)
		public
		pure
		returns (NativeTokenTransfer memory nativeTokenTransfer)
	{
		uint256 index = 0;

		nativeTokenTransfer.amount = encoded.toUint256(index);
		index += 32;

		nativeTokenTransfer.tokenAddress = encoded.toBytes32(index);
		index += 32;

		nativeTokenTransfer.to = encoded.toBytes32(index);
		index += 32;

		nativeTokenTransfer.toChain = encoded.toUint16(index);
	}

	/*
     * @dev Truncate a 32 byte array to a 20 byte address.
     *      Reverts if the array contains non-0 bytes in the first 12 bytes.
     *
     * @param bytes32 bytes The 32 byte array to be converted.
     */
    function _truncateAddress(bytes32 b) internal pure returns (address) {
        require(bytes12(b) == 0, "invalid EVM address");
        return address(uint160(uint256(b)));
    }
}
