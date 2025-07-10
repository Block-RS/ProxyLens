// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SlotTestContract {

    // address 类型：权限控制
    address public owner;

    // bool 类型：初始化标志位
    bool public initialized;

    uint8 public number1;

    uint32 public number2;


    constructor() {
        owner = msg.sender;
    }

    // 初始化函数：写 bool, address
    function initialize() public {
        require(!initialized, "Already initialized");
        initialized = true;
        number1 += 1;
        number2 += 2;
        owner = msg.sender;
    }

    // 权限控制函数：读 address
    function privilegedAction() public view returns (string memory) {
        require(msg.sender == owner, "Not owner");
        return "Privileged action allowed";
    }

}
