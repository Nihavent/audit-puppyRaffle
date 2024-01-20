### [H-#] Reentrancy vulnerability in  `PuppyRaffle::refund` 


### [S-#] Weak RNG in  `PuppyRaffle::selectWinner` 


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

</details>

3. Also consider using [OpenZeppelin's `EnumerableSet` library].
(https://docs.openzeppelin.com/contracts/3.x/api/utils#EnumerableSet)