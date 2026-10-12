// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "./AssayExploit.sol";

/// @title AssayInvariant
/// @notice Base contract of a fixture invariant: a property of the target that every sequence of
///         calls through a handler must keep. Foundry's invariant mode calls the handler with
///         random sequences (runs and depth come from the campaign profile) and checks the
///         property after every call, so that variants made of several calls are found.
/// @dev A fixture implements only `setUpInvariant()`, `invariantName()` and `invariantHolds()`:
///      - `setUpInvariant()` deploys and funds the target, deploys a handler, and registers the
///        handler with `targetContract(address(handler))`, so that only the handler is called;
///      - `invariantName()` is a short label (1 to 32 letters, digits, `_`, `.`, `-`);
///      - `invariantHolds()` reads the state and says whether the property holds.
///      Handler functions must not depend on `msg.sender`: every call of a campaign comes from
///      `INVARIANT_SENDER`, and a replay calls them from the sender that the campaign used.
///
///      `invariant_assay` fails with the reason `ASSAY_INVARIANT_BROKEN|<name>` when the property
///      does not hold. A generated test (`variant_poc.t.sol`) replays the calls of a failing
///      sequence with `assayReplayCall` and ends with `assayCheckInvariant`, which records the
///      predicate `invariant_broken` from the test contract itself.
abstract contract AssayInvariant is AssayExploit {
    /// @notice The sender of every call of an invariant campaign.
    address internal constant INVARIANT_SENDER = address(0xA55a1);

    error AssayInvariantHolds();

    /// @notice Deploys the target and the handler and registers the handler.
    function setUpInvariant() internal virtual;

    /// @notice The label of the invariant, for reports.
    function invariantName() internal pure virtual returns (string memory);

    /// @notice Whether the invariant holds in the current state.
    function invariantHolds() internal view virtual returns (bool);

    function setUp() public {
        setUpInvariant();
        // One fixed sender for every call of a campaign. Forge otherwise draws some senders from
        // a source that its seed does not cover, which makes the reported sequences differ
        // between runs of the same campaign. Handlers do not depend on `msg.sender`.
        targetSender(INVARIANT_SENDER);
    }

    /// @notice Checked by Foundry after every call of a sequence.
    function invariant_assay() public view {
        if (!invariantHolds()) {
            revert(string.concat("ASSAY_INVARIANT_BROKEN|", _checkName(invariantName())));
        }
    }

    /// @notice Replays one call of a counterexample sequence. A call that reverts is ignored, as
    ///         it was during the campaign.
    function assayReplayCall(address sender, address target, bytes memory data) internal {
        vm.prank(sender);
        (bool succeeded,) = target.call(data);
        succeeded;
    }

    /// @notice Ends a replay: records `invariant_broken` when the invariant does not hold, and
    ///         reverts with `AssayInvariantHolds` when it does.
    function assayCheckInvariant() internal {
        if (!invariant_broken(invariantName(), invariantHolds())) revert AssayInvariantHolds();
    }
}
