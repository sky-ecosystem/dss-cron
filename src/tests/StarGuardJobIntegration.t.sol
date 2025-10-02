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
    function file(bytes32 what, uint256 data) external;
    function plot(address addr_, bytes32 tag_) external;
    function prob() external view returns (bool);
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

contract InvalidStarSpell {
    function isExecutable() external pure returns (bool) {
        return true;
    }

    function execute() external pure {
        revert("error");
    }
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

contract MaliciousStarSpell {
    address internal immutable starGuard;

    constructor(address starGuard_) {
        starGuard = starGuard_;
    }

    function isExecutable() external pure returns (bool) {
        return true;
    }

    function execute() external {
        address _starGuard = starGuard;
        assembly {
            // get free memory pointer
            let ptr := mload(64)
            // store starGuard address in the first 32 bytes
            mstore(ptr, _starGuard)
            // store slot index at the next 32 bytes
            mstore(add(ptr, 32), 0)
            // set 0 at the wards[starGuard] slot
            sstore(keccak256(ptr, 64), 0)
        }
    }
}

contract StarGuardJobIntegrationTest is DssCronBaseTest {
    using stdStorage for StdStorage;

    address internal constant unauthedUser = address(0xB0B);
    address internal constant starGuardSpark = address(0x35bb93c01C425Ba940C298E372E1D2ad6df2CA87);
    address internal constant starGuardGrove = address(0x667FC40C9d6e76117937d7d93B948Fb422D97790);

    StarGuardJob public job;
    address public pauseProxy;

    // --- Events ---
    event Add(address indexed starGuard);
    event Remove(address indexed starGuard);
    event Work(bytes32 indexed network, address indexed starGuard, address starSpell);

    function setUpSub() internal virtual override {
        job = new StarGuardJob(address(sequencer));
        pauseProxy = dss.chainlog.getAddress("MCD_PAUSE_PROXY");

        // Init starGuardSpark
        address subProxySpark = StarGuardLike(starGuardSpark).subProxy();
        vm.prank(pauseProxy); SubProxyLike(subProxySpark).rely(starGuardSpark);

        // Init starGuardGrove
        address subProxyGrove = StarGuardLike(starGuardGrove).subProxy();
        vm.prank(pauseProxy); SubProxyLike(subProxyGrove).rely(starGuardGrove);
    }

    function testAuth() public {
        checkAuth(address(job), "StarGuardJob");
    }

    function testAuthModifiers() public {
        bytes4[] memory authedMethods = new bytes4[](2);
        authedMethods[0] = StarGuardJob.add.selector;
        authedMethods[1] = StarGuardJob.remove.selector;

        vm.startPrank(unauthedUser);
        checkModifier(address(job), "StarGuardJob/not-authorized", authedMethods);
        vm.stopPrank();
    }

    function testAdd() public {
        assertEq(job.length(), 0);
        assertFalse(job.has(starGuardSpark));
        vm.expectEmit(true, true, true, true);
        emit Add(starGuardSpark);
        job.add(starGuardSpark);
        assertTrue(job.has(starGuardSpark));
        assertEq(job.length(), 1);
    }

    function testAddDuplicate() public {
        job.add(starGuardSpark);
        assertTrue(job.has(starGuardSpark));
        vm.expectRevert(abi.encodeWithSelector(StarGuardJob.AlreadyAdded.selector, starGuardSpark));
        job.add(starGuardSpark);
        assertEq(job.length(), 1);
    }

    function testRemove() public {
        job.add(starGuardSpark);
        vm.expectEmit(true, true, true, true);
        emit Remove(starGuardSpark);
        job.remove(starGuardSpark);
        assertFalse(job.has(starGuardSpark));
        assertEq(job.length(), 0);
    }

    function testRemoveNotFound() public {
        vm.expectRevert(abi.encodeWithSelector(StarGuardJob.NotFound.selector, starGuardSpark));
        job.remove(starGuardSpark);
    }

    function testWork() public {
        // Prepare jobs
        job.add(starGuardSpark);
        job.add(starGuardGrove);

        // Plot both spells
        address spellSpark = address(new StandardStarSpell());
        vm.prank(pauseProxy); StarGuardLike(starGuardSpark).plot(spellSpark, spellSpark.codehash);
        address spellGrove = address(new StandardStarSpell());
        vm.prank(pauseProxy); StarGuardLike(starGuardGrove).plot(spellGrove, spellGrove.codehash);

        // Check workable state (for Spark)
        {
            uint256 beforeWorkable = vm.snapshot();
            (bool canWork, bytes memory args) = job.workable(NET_A);
            assertTrue(canWork, "unexpected workable() false with spell");
            (address starGuard) = abi.decode(args, (address));
            assertEq(starGuard, starGuardSpark, "unexpected starGuard address");

            // Work
            vm.revertTo(beforeWorkable); // snapshot is required as `workable` modifies state
            vm.expectEmit(true, true, true, true);
            emit Work(NET_A, starGuardSpark, spellSpark);
            job.work(NET_A, args);
            (address addr,,) = StarGuardLike(starGuardSpark).spellData();
            assertEq(addr, address(0), "unexpected starGuard spell after execution");
        }

        // Check workable state (for Grove, after Spark was executed)
        {
            uint256 beforeWorkable = vm.snapshot();
            (bool canWork, bytes memory args) = job.workable(NET_A);
            assertTrue(canWork, "unexpected workable() false with spell");
            (address starGuard) = abi.decode(args, (address));
            assertEq(starGuard, starGuardGrove, "unexpected starGuard address");

            // Work
            vm.revertTo(beforeWorkable); // snapshot is required as `workable` modifies state
            vm.expectEmit(true, true, true, true);
            emit Work(NET_A, starGuardGrove, spellGrove);
            job.work(NET_A, args);
            (address addr,,) = StarGuardLike(starGuardGrove).spellData();
            assertEq(addr, address(0), "unexpected starGuard spell after execution");
        }
    }

    function testWorkWithoutSpell() public {
        job.add(starGuardSpark);
        (bool canWork, bytes memory args) = job.workable(NET_A);
        assertFalse(canWork, "unexpected workable() true with no spell");
        assertEq(args, "No spells to execute", "unexpected calldata with no spell");
    }

    function testWorkWithDelayedSpell() public {
        // Prepare job
        job.add(starGuardSpark);

        // Prepare delayed spell
        uint256 executableAt = block.timestamp + 1 days;
        address delayedStarSpell = address(new DelayedStarSpell(executableAt));

        // Prepare StarGuard
        vm.startPrank(pauseProxy);
        StarGuardLike(starGuardSpark).file("maxDelay", type(uint160).max);
        StarGuardLike(starGuardSpark).plot(delayedStarSpell, delayedStarSpell.codehash);
        vm.stopPrank();

        // Check state immediately
        {
            (bool canWork,) = job.workable(NET_A);
            assertFalse(canWork, "unexpected workable() true with delayed spell: immediate");
        }

        // Check state at executableAt - 1
        {
            vm.warp(executableAt - 1);
            (bool canWork,) = job.workable(NET_A);
            assertFalse(canWork, "unexpected workable() true with delayed spell: almost at executable");
        }

        // Check state at executableAt
        {
            vm.warp(executableAt);
            uint256 beforeWorkable = vm.snapshot();
            (bool canWork, bytes memory args) = job.workable(NET_A);
            assertTrue(canWork, "unexpected workable() false with delayed spell: at executable");
            
            // Work
            vm.revertTo(beforeWorkable); // snapshot is required as `workable` modifies state
            job.work(NET_A, args);
        }
    }

    function testWorkableWithInvalidSpell() public {
        // Prepare job
        job.add(starGuardSpark);

        // Prepare malicious spell
        address maliciousStarSpell = address(new InvalidStarSpell());

        // Prepare StarGuard
        vm.prank(pauseProxy);
        StarGuardLike(starGuardSpark).plot(maliciousStarSpell, maliciousStarSpell.codehash);

        // Ensure that the `prob` returns true, so the spell is technically ready to be executed
        assertTrue(StarGuardLike(starGuardSpark).prob(), "unexpected `prob` value after `plot`");

        // Check workable state
        (bool canWork,) = job.workable(NET_A);
        assertFalse(canWork, "unexpected workable() true with invalid spell");
    }

    function testWorkableWithMaliciousSpell() public {
        // Prepare job
        job.add(starGuardSpark);

        // Prepare malicious spell
        address maliciousStarSpell = address(new MaliciousStarSpell(starGuardSpark));

        // Prepare StarGuard
        vm.prank(pauseProxy);
        StarGuardLike(starGuardSpark).plot(maliciousStarSpell, maliciousStarSpell.codehash);

        // Ensure that the `prob` returns true, so the spell is technically ready to be executed
        assertTrue(StarGuardLike(starGuardSpark).prob(), "unexpected `prob` value after `plot`");

        // Check workable state
        (bool canWork,) = job.workable(NET_A);
        assertFalse(canWork, "unexpected workable() true with malicious spell");
    }
}
