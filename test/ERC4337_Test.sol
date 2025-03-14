// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/account/utils/draft-ERC4337Utils.sol";

contract ERC4337SymbolicTest is Test {
    /*
      Wrapper functions allow memory parameters to be automatically converted to calldata,
      so that library functions (which require calldata) can be called.
    */
    function externalHash(
        PackedUserOperation calldata op,
        address aggregator,
        uint256 nonce
    ) external pure returns (bytes32) {
        return ERC4337Utils.hash(op, aggregator, nonce);
    }

    function externalGasPrice(
        PackedUserOperation calldata op
    ) external view returns (uint256) {
        return ERC4337Utils.gasPrice(op);
    }

    /// @notice Symbolic test verifying that packing and parsing validation data are inverses.
    /// If validUntil is 0, the parse function is expected to return the maximum uint48 value.
    function testPackParseValidationDataConsistent() public pure {
        address aggregator = 0x1234567890123456789012345678901234567890;
        uint48 validAfter = 1000;
        uint48 validUntilNonZero = 2000;
        uint48 validUntilZero = 0;

        // Case 1: validUntil is nonzero
        uint256 packed1 = ERC4337Utils.packValidationData(aggregator, validAfter, validUntilNonZero);
        (address parsedAgg1, uint48 parsedAfter1, uint48 parsedUntil1) = ERC4337Utils.parseValidationData(packed1);
        assertEq(parsedAgg1, aggregator, "Aggregator mismatch for non-zero validUntil");
        assertEq(parsedAfter1, validAfter, "validAfter mismatch for non-zero validUntil");
        assertEq(parsedUntil1, validUntilNonZero, "validUntil mismatch for non-zero validUntil");

        // Case 2: validUntil is zero (indicating "no expiration")
        uint256 packed2 = ERC4337Utils.packValidationData(aggregator, validAfter, validUntilZero);
        (address parsedAgg2, uint48 parsedAfter2, uint48 parsedUntil2) = ERC4337Utils.parseValidationData(packed2);
        assertEq(parsedAgg2, aggregator, "Aggregator mismatch for zero validUntil");
        assertEq(parsedAfter2, validAfter, "validAfter mismatch for zero validUntil");
        assertEq(parsedUntil2, type(uint48).max, "validUntil mismatch for zero validUntil");
    }

    /// @notice Symbolic test for combining validation data with different aggregators.
    function testSymbolicCombineDifferentAggregators(
        address agg1,
        address agg2,
        uint48 validAfter1,
        uint48 validUntil1,
        uint48 validAfter2,
        uint48 validUntil2
    ) public pure {
        if (validUntil1 != 0) vm.assume(validAfter1 <= validUntil1);
        if (validUntil2 != 0) vm.assume(validAfter2 <= validUntil2);
        vm.assume(agg1 != agg2);

        uint256 data1 = ERC4337Utils.packValidationData(agg1, validAfter1, validUntil1);
        uint256 data2 = ERC4337Utils.packValidationData(agg2, validAfter2, validUntil2);
        uint256 combined = ERC4337Utils.combineValidationData(data1, data2);
        (address combAgg, uint48 combAfter, uint48 combUntil) = ERC4337Utils.parseValidationData(combined);

        address expectedAgg = address(1);
        uint48 expectedAfter = (validAfter1 >= validAfter2) ? validAfter1 : validAfter2;
        uint48 normValidUntil1 = (validUntil1 == 0) ? type(uint48).max : validUntil1;
        uint48 normValidUntil2 = (validUntil2 == 0) ? type(uint48).max : validUntil2;
        uint48 expectedUntil = (normValidUntil1 <= normValidUntil2) ? normValidUntil1 : normValidUntil2;

        assertEq(combAgg, expectedAgg, "Symbolic: Aggregator not canonical for different aggregators");
        assertEq(combAfter, expectedAfter, "Symbolic: Combined validAfter incorrect for different aggregators");
        assertEq(combUntil, expectedUntil, "Symbolic: Combined validUntil incorrect for different aggregators");
    }

    /// @notice Symbolic test for combining validation data with the same aggregator.
    function testSymbolicCombineSameAggregator(
        address agg,
        uint48 validAfter1,
        uint48 validUntil1,
        uint48 validAfter2,
        uint48 validUntil2
    ) public pure {
        if (validUntil1 != 0) vm.assume(validAfter1 <= validUntil1);
        if (validUntil2 != 0) vm.assume(validAfter2 <= validUntil2);

        uint256 data1 = ERC4337Utils.packValidationData(agg, validAfter1, validUntil1);
        uint256 data2 = ERC4337Utils.packValidationData(agg, validAfter2, validUntil2);
        uint256 combined = ERC4337Utils.combineValidationData(data1, data2);
        (address combAgg, uint48 combAfter, uint48 combUntil) = ERC4337Utils.parseValidationData(combined);

        address expectedAgg = (agg == address(0)) ? address(0) : address(1);
        uint48 expectedAfter = (validAfter1 >= validAfter2) ? validAfter1 : validAfter2;
        uint48 normValidUntil1 = (validUntil1 == 0) ? type(uint48).max : validUntil1;
        uint48 normValidUntil2 = (validUntil2 == 0) ? type(uint48).max : validUntil2;
        uint48 expectedUntil = (normValidUntil1 <= normValidUntil2) ? normValidUntil1 : normValidUntil2;

        assertEq(combAgg, expectedAgg, "Symbolic: Aggregator mismatch for same aggregator");
        assertEq(combAfter, expectedAfter, "Symbolic: Combined validAfter incorrect for same aggregator");
        assertEq(combUntil, expectedUntil, "Symbolic: Combined validUntil incorrect for same aggregator");
    }

    /// @notice Symbolic test for calculating the user operation hash.
    function testSymbolicHash(
        address sender,
        uint256 nonce,
        bytes memory initCode,
        bytes memory callData,
        uint256 callGasLimit,
        uint256 verificationGasLimit,
        uint256 preVerificationGas,
        uint256 maxFeePerGas,
        uint256 maxPriorityFeePerGas
    ) public view {
        PackedUserOperation memory op = PackedUserOperation(
            sender,
            nonce,
            initCode,
            callData,
            bytes32(callGasLimit),
            verificationGasLimit,
            bytes32(preVerificationGas),
            abi.encode(maxFeePerGas),
            abi.encode(maxPriorityFeePerGas)
        );
        bytes32 hashVal = this.externalHash(op, address(0xABCD), nonce);
        assertTrue(hashVal != bytes32(0), "Symbolic: Hash should not be zero");
    }
}
