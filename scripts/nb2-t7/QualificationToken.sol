// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/// @dev Disposable lane token. TransferFrom charges one base unit in fee mode.
contract QualificationToken {
    bool public immutable chargeFee;
    address public immutable operator = msg.sender;
    address public blocked;
    mapping(address => uint256) private balances;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    constructor(bool chargeFee_) {
        chargeFee = chargeFee_;
    }

    function mint(address recipient, uint256 amount) external {
        require(msg.sender == operator);
        balances[recipient] += amount;
        emit Transfer(address(0), recipient, amount);
    }

    function setBlocked(address recipient) external {
        require(msg.sender == operator);
        blocked = recipient;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function balanceOf(address account) external view returns (uint256) {
        if (chargeFee) expendGas(24_000);
        return balances[account];
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        return move(from, to, amount, chargeFee ? 1 : 0);
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        return move(msg.sender, to, amount, 0);
    }

    function move(address from, address to, uint256 amount, uint256 fee) private returns (bool) {
        require(to != blocked && from != blocked);
        balances[from] -= amount;
        balances[to] += amount - fee;
        emit Transfer(from, to, amount - fee);
        if (fee != 0) emit Transfer(from, address(0), fee);
        if (chargeFee) expendGas(105_000);
        return true;
    }

    // Exercise expensive successful work below the vault's per-call gas caps.
    function expendGas(uint256 amount) private view {
        uint256 threshold = gasleft() - amount;
        assembly ("memory-safe") {
            for {} gt(gas(), threshold) {} {}
        }
    }
}
