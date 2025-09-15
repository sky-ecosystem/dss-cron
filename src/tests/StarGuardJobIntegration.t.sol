// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Dai Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "./DssCronBase.t.sol";

import {StarGuardJob} from "../StarGuardJob.sol";

interface StarGuardLike {
    function exec() external returns (address addr);
    function file(bytes32 what, uint256 data) external;
    function maxDelay() external view returns (uint256 maxDelay);
    function plot(address addr_, bytes32 tag_) external;
    function spellData() external view returns (address addr, bytes32 tag, uint256 deadline);
    function subProxy() external view returns (address subProxy);
}

interface SubProxyLike {
    function rely(address usr) external;
}

contract StandardStarSpell {
    function isExecutable() external pure returns (bool) {
        return true;
    }

    function execute() external {}
}

contract DelayedStarSpell {
    uint256 internal immutable executableAt;

    constructor(uint256 executableAt_) {
        executableAt = executableAt_;
    }

    function isExecutable() external view returns (bool) {
        return block.timestamp >= executableAt;
    }

    function execute() external {}
}

contract StarGuardJobIntegrationTest is DssCronBaseTest {
    using stdStorage for StdStorage;

    address internal constant unauthedUser = address(0xB0B);
    address internal constant starGuardSpark = address(0x35bb93c01C425Ba940C298E372E1D2ad6df2CA87);

    StarGuardJob public job;
    address public pauseProxy;

    // --- Events ---
    event Set(address indexed starGuard);
    event Rem(address indexed starGuard);
    event Work(bytes32 indexed network, address indexed starGuard, address starSpell);

    function setUpSub() internal virtual override {
        job = new StarGuardJob(address(sequencer));
        pauseProxy = dss.chainlog.getAddress("MCD_PAUSE_PROXY");

        // Init starGuardSpark
        address subProxy = StarGuardLike(starGuardSpark).subProxy();
        vm.prank(pauseProxy);
        SubProxyLike(subProxy).rely(starGuardSpark);
    }

    function testAuth() public {
        checkAuth(address(job), "StarGuardJob");
    }

    function testSet() public {
        assertEq(job.length(), 0);
        assertFalse(job.has(starGuardSpark));
        vm.expectEmit(true, true, true, true);
        emit Set(starGuardSpark);
        job.set(starGuardSpark);
        assertTrue(job.has(starGuardSpark));
        assertEq(job.length(), 1);
    }

    function testSetNoAuth() public {
        vm.prank(unauthedUser);
        vm.expectRevert("StarGuardJob/not-authorized");
        job.set(starGuardSpark);
    }

    function testSetDuplicate() public {
        job.set(starGuardSpark);
        assertTrue(job.has(starGuardSpark));
        job.set(starGuardSpark);
        assertTrue(job.has(starGuardSpark));
        assertEq(job.length(), 1);
    }

    function testRem() public {
        job.set(starGuardSpark);
        vm.expectEmit(true, true, true, true);
        emit Rem(starGuardSpark);
        job.rem(starGuardSpark);
        assertFalse(job.has(starGuardSpark));
        assertEq(job.length(), 0);
    }

    function testRemNoAuth() public {
        job.set(starGuardSpark);
        vm.prank(unauthedUser);
        vm.expectRevert("StarGuardJob/not-authorized");
        job.rem(starGuardSpark);
    }

    function testRemNotFound() public {
        vm.expectRevert(abi.encodeWithSelector(StarGuardJob.NotFound.selector, starGuardSpark));
        job.rem(starGuardSpark);
    }

    function testWork() public {
        // Prepare job
        job.set(starGuardSpark);

        // Prepare StarGuard
        address spell = address(new StandardStarSpell());
        vm.prank(pauseProxy);
        StarGuardLike(starGuardSpark).plot(spell, spell.codehash);

        // Check workable state
        uint256 beforeWorkable = vm.snapshot();
        (bool canWork, bytes memory args) = job.workable(NET_A);
        assertTrue(canWork, "unexpected workable() false with spell");
        (address starGuard) = abi.decode(args, (address));
        assertEq(starGuard, starGuardSpark, "unexpected starGuard address");

        // Work
        vm.revertTo(beforeWorkable); // snapshot is required as `workable` modifies state
        vm.expectEmit(true, true, true, true);
        emit Work(NET_A, starGuardSpark, spell);
        job.work(NET_A, args);
        (address addr,,) = StarGuardLike(starGuardSpark).spellData();
        assertEq(addr, address(0), "unexpected starGuard spell after execution");
    }

    function testWorkWithoutSpell() public {
        job.set(starGuardSpark);
        (bool canWork, bytes memory args) = job.workable(NET_A);
        assertFalse(canWork, "unexpected workable() true with no spell");
        assertEq(args, "No distribution", "unexpected calldata with no spell");
    }

    function testWorkWithDelayedSpell() public {
        // Prepare job
        job.set(starGuardSpark);

        // Prepare delayed spell
        uint256 executableAt = block.timestamp + 1 days;
        address delayedStarSpell = address(new DelayedStarSpell(executableAt));

        // Prepare StarGuard
        vm.startPrank(pauseProxy);
        StarGuardLike(starGuardSpark).file("maxDelay", type(uint160).max);
        StarGuardLike(starGuardSpark).plot(delayedStarSpell, delayedStarSpell.codehash);
        vm.stopPrank();

        // Check workable state immidiately
        {
            (bool canWork,) = job.workable(NET_A);
            assertFalse(canWork, "unexpected workable() true with delayed spell: immidiate");
        }

        // Check workable state at executableAt - 1
        {
            vm.warp(executableAt - 1);
            (bool canWork,) = job.workable(NET_A);
            assertFalse(canWork, "unexpected workable() true with delayed spell: almost at executable");
        }

        // Check workable state at executableAt
        vm.warp(executableAt);
        uint256 beforeWorkable = vm.snapshot();
        (bool canWork, bytes memory args) = job.workable(NET_A);
        assertTrue(canWork, "unexpected workable() false with delayed spell: at executable");

        // Work
        vm.revertTo(beforeWorkable); // snapshot is required as `workable` modifies state
        job.work(NET_A, args);
    }
}
