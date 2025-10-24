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

import {IJob} from "./interfaces/IJob.sol";
import "./utils/EnumerableSet.sol";

interface SequencerLike {
    function isMaster(bytes32 network) external view returns (bool);
}

interface StarGuardLike {
    function prob() external view returns (bool result);
    function exec() external returns (address addr);
}

/// @title Execute Star payloads `plot`ted in StarGuard
contract StarGuardJob is IJob {
    using EnumerableSet for EnumerableSet.AddressSet;

    // --- storage variables ---

    /// @notice Address with admin access to this contract
    mapping(address => uint256) public wards;

    /// @notice Iterable set of StarGuard contracts added to the job
    EnumerableSet.AddressSet private starGuards;

    // --- immutables ---

    /// @notice Keeper Network sequencer
    SequencerLike public immutable sequencer;

    // --- errors ---

    /**
     * @notice The keeper trying to execute `work` is not the current master
     * @param network The keeper identifier
     */
    error NotMaster(bytes32 network);

    /// @notice No args were provided to `work`.
    error NoArgs();

    /**
     * @notice The StarGuard contract was not added to the job.
     * @param starGuard The StarGuard contract
     */
    error NotFound(address starGuard);

    /**
     * @notice The StarGuard contract was already added to the job.
     * @param starGuard The StarGuard contract
     */
    error AlreadyAdded(address starGuard);

    // --- events ---

    /**
     * @notice `usr` was granted admin access.
     * @param usr The user address.
     */
    event Rely(address indexed usr);

    /**
     * @notice `usr` admin access was revoked.
     * @param usr The user address.
     */
    event Deny(address indexed usr);

    /**
     * @notice A StarGuard contract was added to or modified in the job
     * @param starGuard The StarGuard contract
     */
    event Add(address indexed starGuard);

    /**
     * @notice A StarGuard contract was removed from the job
     * @param starGuard The removed StarGuard contract
     */
    event Rem(address indexed starGuard);

    /**
     * @notice Work os executed
     * @param network The keeper who executed the job
     * @param starGuard The StarGuard which executed the payload
     * @param starSpell The payload address
     */
    event Work(bytes32 indexed network, address indexed starGuard, address starSpell);

    // --- modifiers ---

    /**
     * @notice Check if sender is authorized
     */
    modifier auth() {
        require(wards[msg.sender] == 1, "StarGuardJob/not-authorized");
        _;
    }

    // --- constructor ---

    /**
     * @param _sequencer The keeper network sequencer.
     */
    constructor(address _sequencer) {
        sequencer = SequencerLike(_sequencer);

        wards[msg.sender] = 1;
        emit Rely(msg.sender);
    }

    // --- administration ---

    /**
     * @notice Grants `usr` admin access to this contract
     * @param usr The user address
     */
    function rely(address usr) external auth {
        wards[usr] = 1;
        emit Rely(usr);
    }

    /**
     * @notice Revokes `usr` admin access from this contract
     * @param usr The user address
     */
    function deny(address usr) external auth {
        wards[usr] = 0;
        emit Deny(usr);
    }

    /**
     * @notice Adds the StarGuard contract in the job
     * @param starGuard The StarGuard contract to add
     */
    function add(address starGuard) external auth {
        if (!starGuards.add(starGuard)) revert AlreadyAdded(starGuard);
        emit Add(starGuard);
    }

    /**
     * @notice Removes the StarGuard contract from the job
     * @param starGuard The StarGuard contract to remove
     */
    function rem(address starGuard) external auth {
        if (!starGuards.remove(starGuard)) revert NotFound(starGuard);
        emit Rem(starGuard);
    }

    // --- getters ---

    /**
     * @notice Output the amount of active starGuards
     * @return length The amount of active starGuards
     */
    function length() public view returns (uint256) {
        return starGuards.length();
    }

    /**
     * @notice Checks if the job has the specified StarGuard contract
     * @param starGuard The StarGuard contract
     * @return Whether The StarGuard is already there
     */
    function has(address starGuard) public view returns (bool) {
        return starGuards.contains(starGuard);
    }

    // --- keeper network interface ---

    /**
     * @notice Executes the job though the keeper network.
     * @param network The keeper identifier.
     * @param args The arguments for execution.
     */
    function work(bytes32 network, bytes calldata args) external {
        if (!sequencer.isMaster(network)) revert NotMaster(network);
        if (args.length == 0) revert NoArgs();

        (address starGuard) = abi.decode(args, (address));
        // Ensures starGuard was not removed in the meantime
        if (!has(starGuard)) revert NotFound(starGuard);

        address spell = StarGuardLike(starGuard).exec();
        emit Work(network, starGuard, spell);
    }

    /**
     * @notice Checks if there is work to be done in the job.
     * @dev Most providers define a gas limit for `eth_call` requests to prevent DoS.
     *      Notice that hitting that limit is higly unlikely, as it would require hundreds or thousands of active
     *      contracts in this job.
     *      Keepers are expected to take that into consideration, especially if they are using self-hosted
     *      infrastructure, which might have arbitrary values configured.
     * @param network The keeper identifier.
     * @return ok Whether it should execute or not.
     * @return args The args for execution.
     */
    function workable(bytes32 network) external override returns (bool ok, bytes memory args) {
        if (!sequencer.isMaster(network)) return (false, bytes("Network is not master"));

        uint256 len = starGuards.length();
        for (uint256 i = 0; i < len; i++) {
            address starGuard = starGuards.at(i);
            try this.work(network, abi.encode(starGuard)) {
                return (true, abi.encode(starGuard));
            } catch {
                continue;
            }
        }
        return (false, bytes("No spells to execute"));
    }
}
