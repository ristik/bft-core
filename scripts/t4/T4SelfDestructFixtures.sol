// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.28;

/// @dev Under Cancun, creation and self-destruction in one transaction with self as
/// beneficiary burns the constructor value and removes the new account.
contract SameTransactionSelfDestructToSelf {
    constructor() payable {
        selfdestruct(payable(address(this)));
    }
}

/// @dev When destroyed in a later transaction, Cancun transfers the balance but
/// keeps this contract's code and storage.
contract ExistingSelfDestruct {
    address payable public immutable beneficiary;

    constructor(address payable beneficiary_) payable {
        require(beneficiary_ != address(0), "zero beneficiary");
        beneficiary = beneficiary_;
    }

    function destroy() external {
        selfdestruct(beneficiary);
    }
}
