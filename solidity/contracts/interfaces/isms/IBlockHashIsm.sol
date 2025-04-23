// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.6.11;

/*@@@@@@@       @@@@@@@@@
 @@@@@@@@@       @@@@@@@@@
  @@@@@@@@@       @@@@@@@@@
   @@@@@@@@@       @@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@
     @@@@@  HYPERLANE  @@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@
   @@@@@@@@@       @@@@@@@@@
  @@@@@@@@@       @@@@@@@@@
 @@@@@@@@@       @@@@@@@@@
@@@@@@@@@       @@@@@@@@*/

import {IInterchainSecurityModule} from "../IInterchainSecurityModule.sol";
import {IBlockHashOracle} from "../IBlockHashOracle.sol";

interface IBlockHashIsm is IInterchainSecurityModule {
    function blockHashOracles(
        uint32 _origin
    ) external view returns (IBlockHashOracle);

    function originMailboxAddresses(
        uint32 _origin
    ) external view returns (address);

    function setBlockHashOracle(
        uint32 _origin,
        address _blockHashOracle
    ) external;

    function setOriginMailboxAddress(
        uint32 _origin,
        address _mailboxAddress
    ) external;
}
