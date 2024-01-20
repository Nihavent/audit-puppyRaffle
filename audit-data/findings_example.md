### [H-1] Storing the password on-chain makes it visible to anyone

**Description**

All data stored on-chain is visible to anyone, and can be read directly from the blockcahin. The `PasswordStore::s_password` variable is intended to only be visible to the owner of the contract through the `PasswordStore::getPassword` function.

**Impact**

Anyone can read the private password, severly breaking the functionaility of the protocol.

**Proof of Concept** (proof of code)

The below test case shows how anyone can read the password directly from the blockchain.

1. Create a locally running chain 

```bash
make anvil
```

2. Deploy the contract to the chain 

```bash
make deploy
```

3. Run the storage tool 

We use `1` because that's the storage slot of `PasswordStores_password` in the contract.

```bash
cast storage <CONTRACT ADDRESS> 1 --rpc-url http://127.0.0.1:8545
```

You'll get an output that looks like this:

`0x6d7950617373776f726400000000000000000000000000000000000000000014`

Parse the hex to a string:

```bash
cast parse-bytes32-string 0x6d7950617373776f726400000000000000000000000000000000000000000014
```

And get an output of:

`myPassword`


**Recommended Mitigation**

The overall architecture of the contract should be rethought. One could encrypt the password off-chain, and then store the encrypted password on-chain. This would require the user to remember another password off-chain to decrypt the password.
This would present a new risk such as the user accidently sending a transaction with the password that decrypts the actual password, instead of their new desired password.



### [H-2] TITLE `PasswordStore::s_password` has no access controls, meaning a non-owner could change the password.

**Description**

The `PasswordStore::s_password` function is set to be an `external` function, however, the natspec of the function and overall purpose of the smart contract says that `This function allows only the owner to set a new password.`

**Impact**

```javascript
    function setPassword(string memory newPassword) external {
@>      // @audit - There are no access controls
        s_password = newPassword;
        emit SetNetPassword();
    }
```

Anyone can set/change the password of trhe contract, breaking the intended functionality of the control. 

**Proof of Concept** (proof of code)

Add the following to the `PasswordStore.t.sol` test file:

<details>
<summary>Code</summary>

````javascript
    function testAnyoneCanSetPassword(address randomAddress) public {
        vm.assume(randomAddress != owner);

        // Setting password as a random address
        vm.prank(randomAddress);
        string memory expectedPassword = "myNewPassword";
        passwordStore.setPassword(expectedPassword);

        // Checking password as the owner
        vm.prank(owner);
        string memory actualPassword = passwordStore.getPassword();
        assertEq(actualPassword, expectedPassword);
    }
````

</details>


**Recommended Mitigation**

Add an access control conditional to the `PasswordStore::setPassword` function. 

```javascript
if(msg.sender != s_owner) {
    revert PasswordStore__NotOwner();
}
```





### [I-1] TITLE The `PasswordStore::getPassword` natspec indicates a parameter that doesn't exist.

**Description**

```javascript
    /*
     * @notice This allows only the owner to retrieve the password.
@>   * @param newPassword The new password to set.
     */
    function getPassword() external view returns (string memory) {
```

The `PasswordStore::getPassword` function signature is `getPassword()` while the natspec says it should be `getPassword(string newPassword)`

**Impact**

The natspec is incorrect.

**Proof of Concept** (proof of code)

**Recommended Mitigation** Remove the incorrect natspec line.

```diff
-    * @param newPassword The new password to set.
```