// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

// ============ External Imports ============
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

// ============ Internal Imports ============
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {IBlockHashIsm} from "../../interfaces/isms/IBlockHashIsm.sol";
import {IBlockHashOracle} from "../../interfaces/IBlockHashOracle.sol";
import {Message} from "../../libs/Message.sol";
import {TypeCasts} from "../../libs/TypeCasts.sol";
import {MerklePatriciaProof} from "../../libs/MerklePatriciaProof.sol";
import {RLPReader} from "../../libs/RLPReader.sol";
import {PackageVersioned} from "../../PackageVersioned.sol";

/**
 * @title BlockHashIsm
 * @notice
 */

// ============ ASSUMPTIONS ============
// Relayers are untrusted
// Blockhash oracles are trusted
// Metadata field is
// Message ID is keccak256 of the message
// Finding the associated logbloom of 'DispatchId(bytes32 indexed messageId )' is the cheapest way to match a blocks succesful inclusion of the message;
// without verifying the canonical address for the mailbox on the origin chain, it is very easy to spoof this check, as it would pass the existence check as long as the log matches the format of the mailbox dispatch event

contract BlockHashIsm is IBlockHashIsm, Ownable, PackageVersioned {
    using Message for bytes;
    using TypeCasts for bytes32;
    using TypeCasts for address;
    using Address for address;
    using Strings for uint32;
    using RLPReader for bytes;
    using RLPReader for RLPReader.RLPItem;
    using MerklePatriciaProof for bytes;
    // ============ Storage ============
    // The origin chain of the message -> the blockhash oracle for the origin chain
    mapping(uint32 => IBlockHashOracle) public blockHashOracles;
    mapping(uint32 => address) public originMailboxAddresses;

    // solhint-disable-next-line const-name-snakecase
    uint8 public constant moduleType =
        uint8(IInterchainSecurityModule.Types.BLOCKHASH);

    // ============ Constructor ============
    constructor() {}

    // ============ External Admin Functions ============

    function setBlockHashOracle(
        uint32 _origin,
        address _blockHashOracle
    ) external onlyOwner {
        require(
            _blockHashOracle != address(0),
            "BlockHashIsm: Blockhash Oracle cannot be zero address"
        );
        blockHashOracles[_origin] = IBlockHashOracle(_blockHashOracle);
    }

    function setOriginMailboxAddress(
        uint32 _origin,
        address _mailbox
    ) external onlyOwner {
        require(
            _mailbox != address(0),
            "BlockHashIsm: Mailbox cannot be zero address"
        );
        originMailboxAddresses[_origin] = _mailbox;
    }

    // ============ Public Functions ============

    /***
    VIA RETH:primitives Struct Header
    pub struct Header {
        [0]pub parent_hash: FixedBytes<32>,
        [1]pub ommers_hash: FixedBytes<32>,
        [2]pub beneficiary: Address,
        [3]pub state_root: FixedBytes<32>,
        [4]pub transactions_root: FixedBytes<32>,
        [5]pub receipts_root: FixedBytes<32>,
        [6]pub logs_bloom: Bloom,
        [7]pub difficulty: Uint<256, 4>,
        [8]pub number: u64,
        [9]pub gas_limit: u64,
        [10]pub gas_used: u64,
        [11]pub timestamp: u64,
        [12]pub extra_data: Bytes,
        [13]pub mix_hash: FixedBytes<32>,
        [14]pub nonce: FixedBytes<8>,
        [15]pub base_fee_per_gas: Option<u64>,
        [16]pub withdrawals_root: Option<FixedBytes<32>>,
        [17]pub blob_gas_used: Option<u64>,
        [18]pub excess_blob_gas: Option<u64>,
        [19]pub parent_beacon_block_root: Option<FixedBytes<32>>,
        [20]pub requests_hash: Option<FixedBytes<32>>,
    }
    */

    /**
     * @notice Verifies that a message was dispatched, by proving inclusion of a DispatchId log (from the mailbox)
     * in a receipt, using a Merkle Patricia proof against the receipts trie of a block,
     * whose hash is verified via a trusted block hash oracle.
     * @param _metadata is abi encoded block header(rlp) + transaction receipt (rlp) + receipt trie key + receipt trie nodes
     * bytes rlpBlockHeader [in full to verify the blockhash]
     * bytes expectedReceiptRlp
     * bytes receiptTrieKey,
     * bytes32 encodedTrieNodes
     * @param _message Formatted Hyperlane message (see Message.sol).
     */
    struct verifyLocalVars {
        bytes rlpBlockHeader;
        bytes expectedReceiptRlp;
        bytes receiptTrieKey;
        bytes encodedTrieNodes;
        uint32 originDomain;
        uint256 blockNumber;
        bytes32 blockHash;
        bytes32 computedBlockHash;
        bytes32 receiptsRoot;
        bytes32 dispatchIDSignature;
        bytes32 messageID;
        uint256 i;
        address emitter;
        bytes32 topic0;
        bytes32 topic1;
    }

    function verify(
        bytes calldata _metadata,
        bytes calldata _message
    ) public view returns (bool) {
        verifyLocalVars memory vars;
        (
            vars.rlpBlockHeader,
            vars.expectedReceiptRlp,
            vars.receiptTrieKey,
            vars.encodedTrieNodes
        ) = abi.decode(_metadata, (bytes, bytes, bytes, bytes));

        {
            vars.originDomain = Message.origin(_message);
            RLPReader.RLPItem[] memory blockHeader = vars
                .rlpBlockHeader
                .toRlpItem()
                .toList();
            vars.blockNumber = blockHeader[8].toUint();
            vars.blockHash = blockHashOracles[vars.originDomain].blockhash(
                vars.blockNumber
            );
            require(vars.blockHash != bytes32(0), "Blockhash Not Found");
            vars.computedBlockHash = keccak256(vars.rlpBlockHeader);
            require(
                vars.blockHash == vars.computedBlockHash,
                "Blockhash Mismatch"
            );
            vars.receiptsRoot = bytes32(blockHeader[5].toBytes());
        }

        require(
            MerklePatriciaProof.verify(
                vars.expectedReceiptRlp,
                vars.receiptTrieKey,
                vars.encodedTrieNodes,
                vars.receiptsRoot
            ),
            "Invalid Receipt Proof"
        );

        RLPReader.RLPItem[] memory receipt = vars
            .expectedReceiptRlp
            .toRlpItem()
            .toList();

        /***
        From RETH:primitives Struct Receipt
        pub struct Receipt {
            pub tx_type: TxType,
            pub success: bool,
            pub cumulative_gas_used: u64,
            pub logs: Vec<Log>,
        }
        */

        require(receipt.length > 3, "Transaction Malformed");
        require(receipt[1].toUint() == 1, "Transaction Reverted");

        RLPReader.RLPItem[] memory logs = receipt[3].toList();
        vars.dispatchIDSignature = keccak256("DispatchId(bytes32)");
        vars.messageID = _message.id();
        for (vars.i = 0; vars.i < logs.length; vars.i++) {
            RLPReader.RLPItem[] memory log = logs[vars.i].toList();

            vars.emitter = log[0].toAddress();
            if (vars.emitter != originMailboxAddresses[vars.originDomain]) {
                continue;
            }

            RLPReader.RLPItem[] memory topics = log[1].toList();
            if (topics.length < 2) {
                continue;
            }
            vars.topic0 = bytes32(topics[0].toUint());
            vars.topic1 = bytes32(topics[1].toUint());
            if (
                vars.topic0 == vars.dispatchIDSignature &&
                vars.topic1 == vars.messageID
            ) {
                return true;
            }
        }

        revert("DispatchId Log Not Found");
    }
}
