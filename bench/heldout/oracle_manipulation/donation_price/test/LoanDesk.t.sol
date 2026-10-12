// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AssayExploit} from "assay/AssayExploit.sol";
import {PlainToken} from "../src/PlainToken.sol";
import {ReferencePool} from "../src/ReferencePool.sol";
import {LoanDesk} from "../src/LoanDesk.sol";

/// @notice Ordinary use of the pool and the desk. Every test records what an outside observer
///         can see.
contract LoanDeskBenignTest is AssayExploit {
    PlainToken internal asset;
    PlainToken internal usd;
    ReferencePool internal pool;
    LoanDesk internal desk;
    address internal lp = makeAddr("lp");
    address internal alice = makeAddr("alice");

    function setUp() public {
        asset = new PlainToken();
        usd = new PlainToken();
        pool = new ReferencePool(asset, usd);
        desk = new LoanDesk(pool);

        asset.mint(lp, 1_000e18);
        usd.mint(lp, 2_000e18);
        vm.startPrank(lp);
        asset.approve(address(pool), type(uint256).max);
        usd.approve(address(pool), type(uint256).max);
        pool.deposit(1_000e18, 2_000e18);
        vm.stopPrank();

        usd.mint(address(desk), 100_000e18);
        asset.mint(alice, 500e18);
        usd.mint(alice, 1_000e18);
        vm.startPrank(alice);
        asset.approve(address(desk), type(uint256).max);
        usd.approve(address(desk), type(uint256).max);
        vm.stopPrank();
    }

    function test_the_price_is_the_ratio_of_the_pool() public {
        assertEq(pool.price(), 2e18);

        asset.mint(lp, 500e18);
        usd.mint(lp, 1_000e18);
        vm.prank(lp);
        pool.deposit(500e18, 1_000e18);
        assertEq(pool.price(), 2e18);
        recordBehavior("price", abi.encode(pool.price(), asset.balanceOf(address(pool)), usd.balanceOf(address(pool))));
    }

    function test_locked_collateral_sets_the_loan_limit() public {
        vm.prank(alice);
        desk.lock(100e18);

        assertEq(desk.lockedOf(alice), 100e18);
        assertEq(desk.maxLoan(alice), 150e18);
        recordBehavior("limit", abi.encode(desk.lockedOf(alice), desk.maxLoan(alice)));
    }

    function test_borrow_and_repay() public {
        vm.startPrank(alice);
        desk.lock(100e18);
        desk.borrow(120e18);
        assertEq(usd.balanceOf(alice), 1_120e18);
        desk.repay(20e18);
        vm.stopPrank();

        assertEq(desk.owedBy(alice), 100e18);
        assertEq(usd.balanceOf(alice), 1_100e18);
        recordBehavior("borrow_repay", abi.encode(desk.owedBy(alice), usd.balanceOf(alice), usd.balanceOf(address(desk))));
    }

    function test_borrowing_above_the_limit_reverts() public {
        vm.startPrank(alice);
        desk.lock(100e18);
        vm.expectRevert(abi.encodeWithSelector(LoanDesk.LoanTooLarge.selector, 151e18, 150e18));
        desk.borrow(151e18);
        vm.stopPrank();
        recordBehavior("above_limit", abi.encode(desk.owedBy(alice), desk.maxLoan(alice)));
    }

    function test_release_is_limited_by_the_loan() public {
        vm.startPrank(alice);
        desk.lock(100e18);
        desk.borrow(100e18);
        vm.expectRevert(abi.encodeWithSelector(LoanDesk.LoanTooLarge.selector, 100e18, 75e18));
        desk.release(50e18);
        desk.repay(100e18);
        desk.release(100e18);
        vm.stopPrank();

        assertEq(asset.balanceOf(alice), 500e18);
        assertEq(desk.lockedOf(alice), 0);
        recordBehavior("release", abi.encode(desk.lockedOf(alice), desk.owedBy(alice), asset.balanceOf(alice)));
    }

    function test_invalid_amounts_revert() public {
        vm.startPrank(alice);
        vm.expectRevert(LoanDesk.ZeroAmount.selector);
        desk.lock(0);
        desk.lock(10e18);
        vm.expectRevert(LoanDesk.ZeroAmount.selector);
        desk.borrow(0);
        vm.expectRevert(abi.encodeWithSelector(LoanDesk.NotEnoughLocked.selector, 11e18, 10e18));
        desk.release(11e18);
        vm.expectRevert(abi.encodeWithSelector(LoanDesk.RepayTooMuch.selector, 1e18, 0));
        desk.repay(1e18);
        vm.stopPrank();

        vm.expectRevert(ReferencePool.ZeroAmount.selector);
        pool.deposit(0, 0);
        recordBehavior("invalid", abi.encode(desk.lockedOf(alice), desk.owedBy(alice)));
    }
}
