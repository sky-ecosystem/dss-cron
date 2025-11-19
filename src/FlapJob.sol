// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2021 Dai Foundation
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

import {IJob} from "./interfaces/IJob.sol";

interface SequencerLike {
    function isMaster(bytes32 network) external view returns (bool);
}

interface KickerLike {
    function flap() external;
}

/// @title Call flap when possible
contract FlapJob is IJob {

    SequencerLike public immutable sequencer;
    KickerLike    public immutable kicker;
    uint256       public immutable maxGasPrice;

    // --- Errors ---
    error NotMaster(bytes32 network);
    error GasPriceTooHigh(uint256 gasPrice, uint256 maxGasPrice);

    // --- Events ---
    event Work(bytes32 indexed network);

    constructor(address _sequencer, address _kicker, uint256 _maxGasPrice) {
        sequencer   = SequencerLike(_sequencer);
        kicker      = KickerLike(_kicker);
        maxGasPrice = _maxGasPrice;
    }

    function work(bytes32 network, bytes calldata) public {
        if (!sequencer.isMaster(network)) revert NotMaster(network);
        if (tx.gasprice > maxGasPrice)    revert GasPriceTooHigh(tx.gasprice, maxGasPrice);

        kicker.flap();

        emit Work(network);
    }

    function workable(bytes32 network) external override returns (bool, bytes memory) {
        if (!sequencer.isMaster(network)) return (false, bytes("Network is not master"));

        bytes memory args = "";
        try this.work(network, args) {
            // Flap succeeds
            return (true, args);
        } catch {
            // Can not flap -- carry on
        }
        return (false, bytes("Flap not possible"));
    }
}
