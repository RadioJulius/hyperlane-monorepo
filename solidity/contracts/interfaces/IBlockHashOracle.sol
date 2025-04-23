pragma solidity >=0.6.11;
// SPDX-License-Identifier: MIT OR Apache-2.0
/*@@@@@@@       @@@@@@@@@
 @@@@@@@@@       @@@@@@@@@
  @@@@@@@@@       @@@@@@@@@
   @@@@@@@@@       @@@@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@
     @@@@@  HYPERLANE  @@@@@@@
    @@@@@@@@@@@@@@@@@@@@@@@@@
   @@@@@@@@@       @@@@@@@@@
  @@@@@@@@@       @@@@@@@@@
 @@@@@@@@@       @@@@@@@@*/
interface IBlockHashOracle {
    function origin() external view returns (uint32);
    function blockhash(uint256 height) external view returns (bytes32 hash);
}
