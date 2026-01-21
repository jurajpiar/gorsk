// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 public value;        // slot 0
    address public owner;        // slot 1
    mapping(uint256 => uint256) public data;  // slot 2 (base)
    
    constructor() {
        value = 42;
        owner = msg.sender;
        data[0] = 100;
        data[1] = 200;
    }
}