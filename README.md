DualGuard - 2nd Layer Multi-Sig Validation Contract
Author: DaAlphaPanda
Year: 2025
Status: Proof-of-Concept / Work in Progress

Overview
DualGuard is a Solidity smart contract designed as an additional security layer for multi-signature (multi-sig) transactions. It provides a full "raw dump" of transaction details (destination address, ETH value, and function call data) before the transaction is signed and executed. This enhanced transparency helps validators detect any spoofing or unauthorized modifications—particularly those that may occur through a compromised front-end interface.

Key Features
Enhanced Transparency:
Every transaction registers its raw data including target address, value, and call data, along with a computed hash to verify its integrity.

Timelock Mechanism:
A configurable delay (1 hour by default) is enforced after registration to give validators sufficient time to review transaction details before execution.

Flexible Approval System:

Normal transactions require a set number of approvals (default: 2).
Transactions flagged as modifying the contract require an extra approval (default: 2 + 1 extra).
Validator-Based Approvals:
Only a predefined list of trusted validator addresses can approve transactions. Each validator can only approve once per transaction.

Prevention of Replay Attacks:
Once a transaction is marked as executed, it cannot be replayed or executed again.

Full Raw Dump for Inspection:
A public function is provided to retrieve all raw details of a transaction, allowing for independent verification of every parameter.

Contract Structure
1. Configuration Constants
REQUIRED_APPROVALS: The number of validator approvals required for normal transactions.
ADDITIONAL_MODIFICATION_APPROVALS: Extra approval needed if a transaction is flagged as modifying the contract.
TIMELOCK: A delay period after transaction registration during which approvals must be gathered.
2. Transaction Data Structure
Each transaction is stored as a struct with the following properties:

target: The destination address for the transaction.
value: Amount of ETH (or token value) to be sent.
data: Encoded function call data.
txHash: A hash computed from the transaction details to ensure integrity.
approvals: Count of approvals the transaction has received.
timestamp: Registration time used to enforce the timelock.
approvedBy: A mapping to ensure each validator only approves once.
executed: A flag that marks whether the transaction has been executed.
modifiesContract: Indicates if the transaction intends to modify the contract (requiring extra scrutiny).
3. Storage Variables
transactions: Mapping of transaction IDs to their corresponding transaction data.
txCount: A counter used to assign unique IDs to transactions.
validators: An array of pre-approved addresses authorized to validate transactions.

How It Works

Transaction Registration:
Call registerTransaction with the transaction's target address, ETH value, encoded data, and a flag indicating whether it modifies the contract. The function computes a hash for integrity and stores all transaction details.

Validator Approval:
Validators call approveTransaction for a given transaction ID. Each validator can only approve once per transaction and must do so before the timelock expires.

Validation Check:
The function isValidated verifies whether the transaction has met the required number of approvals (taking into account extra approvals for modifying transactions) and whether the timelock has passed.

Execution:
Once validated, the transaction can be finalized by calling markExecuted, which marks the transaction as executed and prevents replay.

Inspection:
The getTransactionDetails function allows anyone to retrieve the full "raw dump" of the transaction details to inspect and verify its integrity.

Deployment & Usage
Deploying the Contract:

Compile the Solidity code using a tool like Remix or Hardhat.
Deploy the contract to your desired Ethereum network, passing in the array of trusted validator addresses.
Registering a Transaction:
Call registerTransaction with the following parameters:

_target: Destination address for the transaction.
_value: ETH or token amount to be sent.
_data: The encoded function call data.
_modifiesContract: true if the transaction will modify the contract; otherwise, false.
Approving a Transaction:
Validator addresses call approveTransaction with the transaction ID to register their approval.

Checking Validation:
Use the isValidated function to verify if a transaction meets the required approval threshold and if the timelock has expired.

Executing the Transaction:
Once validated, call markExecuted with the transaction ID to mark it as executed.

Inspecting Transaction Details:
Call getTransactionDetails to retrieve all details of a registered transaction for full transparency.

Developer Notes
Security Considerations:
This contract is a proof-of-concept. In production, consider additional security measures (e.g., role-based access control, off-chain signature aggregation) and thorough auditing.

Extensibility:
The design allows for integration with existing multi-sig wallets or more complex on-chain governance systems. Future iterations may include additional validation layers, integration with oracles, or enhanced logging for compliance.

Timelock & Approval Configurations:
The constants TIMELOCK, REQUIRED_APPROVALS, and ADDITIONAL_MODIFICATION_APPROVALS can be adjusted as needed based on risk tolerance and operational requirements.

License
This project is licensed under the MIT License.

This README provides an overview and detailed explanation of the DualGuard contract, offering insights into its design, functionality, and usage. It is intended to assist developers in understanding and integrating the contract into their projects while ensuring a robust additional layer of security for multi-signature operations.

registerTransaction:
Registers a new transaction by storing all the raw details (destination, value, data, etc.), computes a unique hash for integrity, and sets the initial state (approvals, timestamp, execution flag).

approveTransaction:
Allows authorized validators to approve a transaction. Each validator can only approve once per transaction and must do so within a defined timelock.

isValidated:
Checks whether the transaction has received enough approvals (with an extra vote if it modifies the contract) and whether the timelock period has passed.

markExecuted:
Marks a validated transaction as executed, ensuring that it cannot be replayed or executed multiple times.

getTransactionDetails:
Provides a full "raw dump" of the transaction details so that validators can inspect every parameter and confirm that the transaction matches what was initially registered.


