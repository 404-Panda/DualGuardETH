// SPDX-License-Identifier: MIT
// Dual Guard - DaAlphaPanda 2025 POC
// 2nd Layer Multi-Sig Validation Contract 
// Work in progress
//
// Developer Notes:
// ---------------
// This contract is designed as an additional security layer for multi-signature (multi-sig)
// transactions. Its main goal is to provide full transparency by "raw dumping" all the critical
// details of a transaction (destination address, value, and function call data) for inspection
// before the transaction is signed and executed. This extra level of detail allows validators
// to spot any spoofing or unauthorized modifications that might be introduced by a compromised
// front-end or other malicious actor.
//
// Key features include:
//  - A timelock that gives validators time to review the transaction details.
//  - A flexible approval system that requires more approvals if the transaction modifies the contract.
//  - A public function to retrieve all the raw transaction details for external inspection.
//
// The contract uses an array of pre-approved validator addresses who are authorized to review and
// approve each transaction. Each transaction is stored with its raw data and a computed hash for integrity.
// Once a transaction receives the required number of approvals and the timelock has expired, it can be
// marked as executed, preventing replay or duplicate execution.
//
// This design helps build defense-in-depth by requiring multiple layers of validation before critical operations
// are executed, ensuring that any potential front-end tampering or spoofing is caught early.

pragma solidity ^0.8.0;

contract DualGuard {
    // ---------------------------
    // Configuration Constants
    // ---------------------------
    
    // Number of validator approvals required for normal (non-modifying) transactions.
    uint256 public constant REQUIRED_APPROVALS = 2;
    // Additional approvals required if the transaction intends to modify the contract's state.
    uint256 public constant ADDITIONAL_MODIFICATION_APPROVALS = 1;
    // Time delay (in seconds) after registration of a transaction before it can be executed.
    // This timelock provides a window for validators to review the transaction details.
    uint256 public constant TIMELOCK = 1 hours;

    // ---------------------------
    // Transaction Data Structure
    // ---------------------------
    
    // The Transaction struct holds all the necessary information for each pending transaction.
    // It includes a "raw dump" of all relevant transaction parts and metadata to ensure transparency.
    struct Transaction {
        address target;           // Destination address for the transaction (e.g., contract or wallet)
        uint256 value;            // Amount of ETH (or token value) being sent with the transaction
        bytes data;               // Encoded function call and parameters (raw call data)
        bytes32 txHash;           // Hash of the transaction details for integrity verification
        uint256 approvals;        // Count of validator approvals received so far
        uint256 timestamp;        // Timestamp when the transaction was registered (used for timelock)
        mapping(address => bool) approvedBy; // Mapping to track which validators have approved (to prevent duplicates)
        bool executed;            // Flag indicating whether the transaction has been executed to prevent replay
        bool modifiesContract;    // Flag indicating if the transaction is intended to modify the contract
                                  // (transactions that modify the contract require extra scrutiny)
    }
    
    // ---------------------------
    // Storage Variables
    // ---------------------------
    
    // Mapping to store all transactions using an incremental ID as the key.
    mapping(uint256 => Transaction) public transactions;
    // A simple counter to assign unique IDs to each registered transaction.
    uint256 public txCount;

    // Array of pre-approved validator addresses. These are the entities allowed to approve transactions.
    address[] public validators;

    // ---------------------------
    // Constructor
    // ---------------------------
    
    // The constructor initializes the contract with the list of validator addresses.
    // These validators are trusted entities responsible for reviewing and approving transactions.
    constructor(address[] memory _validators) {
        validators = _validators;
    }
    
    // ---------------------------
    // Modifier: onlyValidator
    // ---------------------------
    
    // This modifier restricts access to certain functions so that only addresses in the validators array can execute them.
    // It loops through the validators list to check if msg.sender is a valid validator.
    modifier onlyValidator() {
        bool valid = false;
        for (uint i = 0; i < validators.length; i++) {
            if (msg.sender == validators[i]) {
                valid = true;
                break;
            }
        }
        require(valid, "Not a validator");
        _;
    }
    
    // ---------------------------
    // Function: registerTransaction
    // ---------------------------
    
    /// @notice Registers a new transaction with its full raw details.
    /// @dev This function creates a new transaction entry that requires multi-sig validation.
    /// It takes the transaction target, ETH value, encoded call data, and a flag indicating if the transaction modifies the contract.
    /// A hash is computed for the transaction details to ensure integrity.
    /// @param _target The destination address where the transaction is directed.
    /// @param _value The amount of ETH (or tokens) to send.
    /// @param _data The raw encoded function call data.
    /// @param _modifiesContract Boolean flag indicating if the transaction intends to modify this contract.
    /// @return txId The unique ID assigned to this transaction.
    function registerTransaction(
        address _target,
        uint256 _value,
        bytes calldata _data,
        bool _modifiesContract
    ) external returns (uint256 txId) {
        // Increment transaction counter to get a new unique transaction ID.
        txCount++;
        // Initialize storage for the new transaction.
        Transaction storage txn = transactions[txCount];
        txn.target = _target;
        txn.value = _value;
        txn.data = _data;
        txn.modifiesContract = _modifiesContract;
        txn.timestamp = block.timestamp;
        txn.approvals = 0;
        txn.executed = false;
        // Compute a unique hash for the transaction using key details.
        // This hash can later be used to verify that the details haven't been altered.
        txn.txHash = keccak256(abi.encodePacked(_target, _value, _data, _modifiesContract, txCount));
        return txCount;
    }
    
    // ---------------------------
    // Function: approveTransaction
    // ---------------------------
    
    /// @notice Allows a validator to approve a pending transaction.
    /// @dev Each validator can approve a given transaction only once. The approval must occur within the timelock period.
    /// @param _txId The unique transaction ID to approve.
    function approveTransaction(uint256 _txId) external onlyValidator {
        Transaction storage txn = transactions[_txId];
        // Ensure that the validator has not already approved this transaction.
        require(!txn.approvedBy[msg.sender], "Already approved");
        // Ensure that the approval is submitted before the timelock expires.
        require(block.timestamp < txn.timestamp + TIMELOCK, "Time-lock expired");
        // Record the validator's approval.
        txn.approvedBy[msg.sender] = true;
        // Increment the approval count.
        txn.approvals += 1;
    }
    
    // ---------------------------
    // Function: isValidated
    // ---------------------------
    
    /// @notice Checks whether a transaction has met the required approvals and timelock conditions.
    /// @dev If a transaction is flagged as modifying the contract, an additional approval is required.
    /// This function is used by the multi-sig wallet to determine if it is safe to execute the transaction.
    /// @param _txId The unique transaction ID to check.
    /// @return True if the transaction has enough approvals and the timelock has passed; otherwise, false.
    function isValidated(uint256 _txId) public view returns (bool) {
        Transaction storage txn = transactions[_txId];
        // Calculate the required approval threshold.
        // If the transaction modifies the contract, add an extra approval requirement.
        uint256 threshold = txn.modifiesContract 
            ? REQUIRED_APPROVALS + ADDITIONAL_MODIFICATION_APPROVALS 
            : REQUIRED_APPROVALS;
        // Check if the transaction meets both the approval threshold and the timelock condition.
        return txn.approvals >= threshold && block.timestamp >= txn.timestamp + TIMELOCK;
    }
    
    // ---------------------------
    // Function: markExecuted
    // ---------------------------
    
    /// @notice Marks a transaction as executed after it has been validated.
    /// @dev This function prevents a transaction from being executed more than once.
    /// Once a transaction is marked as executed, it should not be replayed.
    /// @param _txId The unique transaction ID to mark as executed.
    function markExecuted(uint256 _txId) external {
        // Ensure the transaction has been validated.
        require(isValidated(_txId), "Transaction not validated yet");
        Transaction storage txn = transactions[_txId];
        // Ensure that the transaction hasn't already been executed.
        require(!txn.executed, "Already executed");
        // Mark the transaction as executed.
        txn.executed = true;
        // Additional integration with a multi-sig wallet or further logic can be added here.
    }
    
    // ---------------------------
    // Function: getTransactionDetails
    // ---------------------------
    
    /// @notice Returns all the raw details of a registered transaction for external inspection.
    /// @dev This function provides a complete "raw dump" of the transaction's data, including its target,
    /// value, call data, computed hash, approval count, registration timestamp, execution status,
    /// and whether it modifies the contract.
    /// This is useful for validators to review and verify transaction details before approval.
    /// @param _txId The unique transaction ID whose details are requested.
    /// @return target The destination address of the transaction.
    /// @return value The amount of ETH (or tokens) being transferred.
    /// @return data The raw encoded function call data.
    /// @return txHash The computed hash representing the transaction details.
    /// @return approvals The number of approvals the transaction has received.
    /// @return timestamp The timestamp when the transaction was registered.
    /// @return executed Whether the transaction has already been executed.
    /// @return modifiesContract Whether the transaction is intended to modify this contract.
    function getTransactionDetails(uint256 _txId) external view returns (
        address target,
        uint256 value,
        bytes memory data,
        bytes32 txHash,
        uint256 approvals,
        uint256 timestamp,
        bool executed,
        bool modifiesContract
    ) {
        Transaction storage txn = transactions[_txId];
        return (
            txn.target, 
            txn.value, 
            txn.data, 
            txn.txHash, 
            txn.approvals, 
            txn.timestamp, 
            txn.executed, 
            txn.modifiesContract
        );
    }
}
