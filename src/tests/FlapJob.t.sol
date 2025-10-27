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
pragma solidity 0.8.13;

import "./DssCronBase.t.sol";

import {KickerMock} from "./mocks/KickerMock.sol";
import {FlapJob} from "../FlapJob.sol";

contract FlapJobTest is DssCronBaseTest {
    KickerMock kicker;
    FlapJob    flapJob;

    function setUpSub() virtual override internal {
        kicker = new KickerMock();
        flapJob = new FlapJob(address(sequencer), address(kicker), tx.gasprice);
    }

    function test_flap_succeeds() public {
        kicker.setSucceed(true);

        // snapshot/revert not strictly needed, leaving it so it will still test correctly with a real Kicker that modifies state
        uint256 snapshot = vm.snapshot();
        (bool canWork, bytes memory args) = flapJob.workable(NET_A);
        assertTrue(canWork, "Should be able to work");
        vm.revertTo(snapshot);
        flapJob.work(NET_A, args);
    }

    function test_flap_fails() public {
        kicker.setSucceed(false);

        (bool canWork,) = flapJob.workable(NET_A);
        assertTrue(!canWork, "Should not be able to work");
    }

    function test_flap_gasPriceTooHigh() public {
        kicker.setSucceed(true);
        flapJob = new FlapJob(address(sequencer), address(kicker), tx.gasprice - 1);

        (bool canWork,) = flapJob.workable(NET_A);
        assertTrue(!canWork, "Should not be able to work");
    }
}
