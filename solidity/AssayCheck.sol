// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "./AssayExploit.sol";

/// @title AssayCheck
/// @notice Base contract of symbolic properties, run by Halmos. A property is a public function
///         whose parameters Halmos treats as symbolic: every value of every parameter at once,
///         within the bounds Assay records (loop unrolling, calldata size, calls per property).
/// @dev Two kinds of property, told apart by their name:
///      - `check_variant_<name>(...)`: the exploit, generalized. It calls the target through
///        `assayCall` and ends with one or more `assertNo*` wrappers of the PoC predicates
///        (`attacker_profit`, `victim_loss`, `unauthorized_role_change`, `invariant_broken`).
///        Halmos reports a counterexample when some input makes a predicate hold.
///      - `check_equiv_<name>(...)`: bounded equivalence. It runs the same calls on the revision
///        under test (`src/`) and on the vulnerable revision (`baseline/`, which Assay places in
///        the run tree), with the exploit condition excluded through `vm.assume`, and asserts
///        with `assertSame*` that results and observable state agree.
///      Parameters are static types only (`address`, `bool`, `uintN`, `intN`, `bytesN`), so a
///      property's calldata is 4 + 32 * (number of parameters) bytes. Parameter names contain no
///      `_`, because Halmos derives the reported name from the text between underscores.
///      Fixed accounts are written as constants (for example `address(uint160(0xA11CE0))`), not
///      with `makeAddr` or `vm.addr`: Halmos treats `vm.addr` as an uninterpreted function, so
///      such an account would be symbolic and could coincide with a deployed contract.
///
///      A counterexample is confirmed with Foundry, not with Halmos: a generated test
///      (`variant_poc.t.sol`) derives from the property contract and calls `assayReplayCheck`
///      with the counterexample's calldata. In that replay the `assertNo*` wrappers record the
///      predicate (an `AssayPredicate` event from the test contract, as in a PoC) instead of
///      asserting, and the replay passes only when a predicate held.
abstract contract AssayCheck is AssayExploit {
    /// @notice Calls of the target that one property may make through `assayCall`. Further
    ///         calls revert, so paths beyond the limit end without a counterexample.
    uint256 internal constant ASSAY_MAX_CALLS = 4;

    error AssayNoPredicate();
    error AssayCallLimit(uint256 limit);

    bool private _assayReplaying;
    uint256 private _assayCalls;

    // ---------------------------------------------------------------------------------------
    // Calls of the target.
    // ---------------------------------------------------------------------------------------

    /// @notice Calls `target` with `data` and `value` wei as `caller`; at most `ASSAY_MAX_CALLS`
    ///         times per property. A call that reverts returns `ok = false`.
    function assayCall(address caller, address target, uint256 value, bytes memory data)
        internal
        returns (bool ok, bytes memory result)
    {
        _assayCalls += 1;
        if (_assayCalls > ASSAY_MAX_CALLS) revert AssayCallLimit(ASSAY_MAX_CALLS);
        vm.prank(caller);
        (ok, result) = target.call{value: value}(data);
    }

    // ---------------------------------------------------------------------------------------
    // Predicates. Each asserts that the PoC predicate of the same name does not hold; in a
    // replay it records the predicate instead (see the contract documentation).
    // ---------------------------------------------------------------------------------------

    /// @notice The attacker's holding of `asset` did not grow.
    function assertNoAttackerProfit(string memory asset, uint256 balanceBefore, uint256 balanceAfter)
        internal
    {
        if (_assayReplaying) {
            attacker_profit(asset, balanceBefore, balanceAfter);
            return;
        }
        _checkName(asset);
        assert(balanceAfter <= balanceBefore);
    }

    /// @notice A victim's holding of `asset` did not shrink.
    function assertNoVictimLoss(string memory asset, uint256 balanceBefore, uint256 balanceAfter) internal {
        if (_assayReplaying) {
            victim_loss(asset, balanceBefore, balanceAfter);
            return;
        }
        _checkName(asset);
        assert(balanceAfter >= balanceBefore);
    }

    /// @notice The holder of `role` is still the one that should hold it.
    function assertNoUnauthorizedRoleChange(string memory role, address expectedHolder, address actualHolder)
        internal
    {
        if (_assayReplaying) {
            unauthorized_role_change(role, expectedHolder, actualHolder);
            return;
        }
        _checkName(role);
        assert(actualHolder == expectedHolder);
    }

    /// @notice The invariant `name` holds (`invariantHolds` is true).
    function assertInvariantHolds(string memory name, bool invariantHolds) internal {
        if (_assayReplaying) {
            invariant_broken(name, invariantHolds);
            return;
        }
        _checkName(name);
        assert(invariantHolds);
    }

    // ---------------------------------------------------------------------------------------
    // Equivalence. Used by `check_equiv_*` properties only; never replayed.
    // ---------------------------------------------------------------------------------------

    /// @notice Runs the same call on the revision under test and on the baseline, as `caller`,
    ///         and asserts that both succeed or both revert, with the same return or revert data.
    function assertSameCall(address caller, address underTest, address baseline, bytes memory data)
        internal
        returns (bool ok)
    {
        (bool okUnderTest, bytes memory resultUnderTest) = assayCall(caller, underTest, 0, data);
        (bool okBaseline, bytes memory resultBaseline) = assayCall(caller, baseline, 0, data);
        assert(okUnderTest == okBaseline);
        assert(keccak256(resultUnderTest) == keccak256(resultBaseline));
        return okUnderTest;
    }

    function assertSame(uint256 underTest, uint256 baseline) internal pure {
        assert(underTest == baseline);
    }

    function assertSame(address underTest, address baseline) internal pure {
        assert(underTest == baseline);
    }

    function assertSame(bool underTest, bool baseline) internal pure {
        assert(underTest == baseline);
    }

    // ---------------------------------------------------------------------------------------
    // Replay of a counterexample (Foundry only).
    // ---------------------------------------------------------------------------------------

    /// @notice Runs one property with fixed arguments (`data`: selector and arguments) and
    ///         records its predicates instead of asserting. Reverts with `AssayNoPredicate`
    ///         when no predicate held, and with the property's own revert data when it reverts.
    function assayReplayCheck(bytes memory data) internal {
        _assayReplaying = true;
        _assayCalls = 0;
        assayPredicateCount = 0;
        (bool ok, bytes memory result) = address(this).call(data);
        _assayReplaying = false;
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(result, 32), mload(result))
            }
        }
        if (assayPredicateCount == 0) revert AssayNoPredicate();
    }
}
