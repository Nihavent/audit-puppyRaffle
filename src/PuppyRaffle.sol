// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;
// @report-written use of floating pragma is bad practice, recommend to use fixed version
// @report-written why are you using 0.7.x, use newer version

import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Address} from "@openzeppelin/contracts/utils/Address.sol";
import {Base64} from "lib/base64/base64.sol";

/// @title PuppyRaffle
/// @author PuppyLoveDAO
/// @notice This project is to enter a raffle to win a cute dog NFT. The protocol should do the following:
/// 1. Call the `enterRaffle` function with the following parameters:
///    1. `address[] participants`: A list of addresses that enter. You can use this to enter yourself multiple times, or yourself and a group of your friends.
/// 2. Duplicate addresses are not allowed
/// 3. Users are allowed to get a refund of their ticket & `value` if they call the `refund` function
/// 4. Every X seconds, the raffle will be able to draw a winner and be minted a random puppy
/// 5. The owner of the protocol will set a feeAddress to take a cut of the `value`, and the rest of the funds will be sent to the winner of the puppy.
contract PuppyRaffle is ERC721, Ownable {
    using Address for address payable;

    uint256 public immutable entranceFee;
    
    address[] public players;

    //@report-written this should be immutable to save gas
    uint256 public raffleDuration;
    uint256 public raffleStartTime;
    address public previousWinner;

    // We do some storage packing to save gas
    address public feeAddress;
    uint64 public totalFees = 0;

    // mappings to keep track of token traits
    mapping(uint256 => uint256) public tokenIdToRarity;
    mapping(uint256 => string) public rarityToUri;
    mapping(uint256 => string) public rarityToName;

    // Stats for the common puppy (pug)
    //@report-written should be constant
    string private commonImageUri = "ipfs://QmSsYRx3LpDAb1GZQm7zZ1AuHZjfbPkD6J7s9r41xu1mf8";
    uint256 public constant COMMON_RARITY = 70;
    string private constant COMMON = "common";

    // Stats for the rare puppy (st. bernard)
    //@report-written should be constant
    string private rareImageUri = "ipfs://QmUPjADFGEKmfohdTaNcWhp7VGk26h5jXDA7v3VtTnTLcW";
    uint256 public constant RARE_RARITY = 25;
    string private constant RARE = "rare";

    // Stats for the legendary puppy (shiba inu)
    //@report-written should be constant
    string private legendaryImageUri = "ipfs://QmYx6GsYAKnNzZ9A6NvEKV9nf1VaDzJrqDR23Y8YSkebLU";
    uint256 public constant LEGENDARY_RARITY = 5;
    string private constant LEGENDARY = "legendary";

    // Events
    //@report-written no indexed fields (Aderyn)
    event RaffleEnter(address[] newPlayers);
    event RaffleRefunded(address player);
    event FeeAddressChanged(address newFeeAddress);

    /// @param _entranceFee the cost in wei to enter the raffle
    /// @param _feeAddress the address to send the fees to
    /// @param _raffleDuration the duration in seconds of the raffle
    constructor(uint256 _entranceFee, address _feeAddress, uint256 _raffleDuration) ERC721("Puppy Raffle", "PR") {
        entranceFee = _entranceFee;
        //@report-written check for zero address, input validation
        feeAddress = _feeAddress;
        raffleDuration = _raffleDuration;
        raffleStartTime = block.timestamp;

        rarityToUri[COMMON_RARITY] = commonImageUri;
        rarityToUri[RARE_RARITY] = rareImageUri;
        rarityToUri[LEGENDARY_RARITY] = legendaryImageUri;

        rarityToName[COMMON_RARITY] = COMMON;
        rarityToName[RARE_RARITY] = RARE;
        rarityToName[LEGENDARY_RARITY] = LEGENDARY;
    }

    /// @notice this is how players enter the raffle
    /// @notice they have to pay the entrance fee * the number of players
    /// @notice duplicate entrants are not allowed
    /// @param newPlayers the list of players to enter the raffle
    function enterRaffle(address[] memory newPlayers) public payable {
        // q - were custom reverts avaialble in this version of solidity?
        // q - what if msg.value is zero?
        // @report-skipped - this should check if an address entered is a zero address -  you cannot mint erc721 to a zero address    
        // @report-written -gas use uint256 playerLength instead of players.length, as this is calling data from storage twice in this function 
        require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
        for (uint256 i = 0; i < newPlayers.length; i++) {
            // q what resets the players array?
            players.push(newPlayers[i]);
        }

        // Check for duplicates
        // @report-written DOS Attack
        for (uint256 i = 0; i < players.length - 1; i++) { 
            for (uint256 j = i + 1; j < players.length; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
            }
        }
        //@report-skipped - If an empty array is submitted this will emit an empty event
        emit RaffleEnter(newPlayers);
    }

    /// @param playerIndex the index of the player to refund. You can find it externally by calling `getActivePlayerIndex`
    /// @dev This function will allow there to be blank spots in the array

    // @report-written - reentrancy vulnerability due to this function sending a balance before the player is removed from the array.
    // @report-written -   if the player is a contract, they can call this function and re-enter the raffle before they are removed from the array (using their fallback() or receive() function)
    // @q - if an address is changed to zero, can this address still win the raffle?
    function refund(uint256 playerIndex) public {
        // @report-skipped MEV
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

        //@report-written- makes external call before updates state
        payable(msg.sender).sendValue(entranceFee);

        players[playerIndex] = address(0); //@report-skipped - note when a player is refunded they keep their place in the array, conttributing to array length.
        //@report-written  event emitted after call
        emit RaffleRefunded(playerAddress);
    }

    /// @notice a way to get the index in the array
    /// @param player the address of a player in the raffle
    /// @return the index of the player in the array, if they are not active, it returns 0
    function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        // @report-written if the player is at index 0, this returns 0 and a player might think they're not active.
        return 0;
    }

    /// @notice this function will select a winner and mint a puppy
    /// @notice there must be at least 4 players, and the duration has occurred
    /// @notice the previous winner is stored in the previousWinner variable
    /// @dev we use a hash of on-chain data to generate the random numbers
    /// @dev we reset the active players array after the winner is selected
    /// @dev we send 80% of the funds to the winner, the other 20% goes to the feeAddress

    // @report-written - recommend to follow CEI
    // @q - who calls this function? Should it by called by a Chainlink automated job?
    function selectWinner() external {
        // q - are the raffle duration and start time being set correctly?
        require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        require(players.length >= 4, "PuppyRaffle: Need at least 4 players"); // @report-skipped - this checks length of array, but not length of array excluding zero addresses (refunded entrants)
        
        // @report-written - weak RNG, fixes Chainlink VRF, Commit Reveal Scheme
        // @report-skipped - picks a winner from the players array, but the winner can still be a zero adress (either refunded player or entered zero address)
        uint256 winnerIndex =
            uint256(keccak256(abi.encodePacked(msg.sender, block.timestamp, block.difficulty))) % players.length; // I'm not sure this is actually random, we could use Chainlink VRF instead
        address winner = players[winnerIndex];
        uint256 totalAmountCollected = players.length * entranceFee; // @report-skipped - This will overcount if there are refunded players
        //@report-skipped - probably some precision loss here
        //@report-written magic numbers are bad practice
        uint256 prizePool = (totalAmountCollected * 80) / 100;
        uint256 fee = (totalAmountCollected * 20) / 100;
        //@report-written - overflow when this value exceeds 2^64, with an entrance fee of 1e18, this will overflow after 2^64 / (0.2 * 1e18) ~ 93 players
        // max value: 18446744073709551615
        //@report-written, included in overflow issue - unsafe cast of uint256 to uint64, will lose fees as soon as they exceed 18.4 ether.
        totalFees = totalFees + uint64(fee);

        uint256 tokenId = totalSupply(); //q - should this be totalSupply() + 1?

        // We use a different RNG calculate from the winnerIndex to determine rarity
        //@report-written - weak RNG
        //@report-written - people can revert the TX till they get a legendary NFT.
        uint256 rarity = uint256(keccak256(abi.encodePacked(msg.sender, block.difficulty))) % 100; // @audit - not truly random - picks a random number between 0 and 99.
        if (rarity <= COMMON_RARITY) { // @n x <= 70 then common
            tokenIdToRarity[tokenId] = COMMON_RARITY;
        } else if (rarity <= COMMON_RARITY + RARE_RARITY) { //@n x between 71 and 95 then rare
            tokenIdToRarity[tokenId] = RARE_RARITY;
        } else {
            tokenIdToRarity[tokenId] = LEGENDARY_RARITY; //@n x between 96 and 99 then legendary
        }

        delete players; // n - resets the players array
        raffleStartTime = block.timestamp;
        previousWinner = winner;

        //n - ReEntrancy might be protected by this code: require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
        //@report-written - what would happen if the winner didn't have their fallback setup correctly?
        (bool success,) = winner.call{value: prizePool}("");  // @report-skipped - prizePool may be too large if there are refunded players 
        require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner, tokenId);
    }

    /// @notice this function will withdraw the fees to the feeAddress
    // q - should this be external?
    // q - who should be able to call this function?
    function withdrawFees() external { 
        //@report-written under the integer overflow issue, ideally separate this out in competitive audit - mishandling ether can lead to a DoS attack, if someone can send funds to this contract without the totalFees variable being updated, then the contract will be unable to withdraw fees.
        //@report-skipped, this line of code also enables griefing due to difficulty of withdrawing funds. ie, people enter raffle as soon as it opens so owner can never withdraw, or users forcing eth onto this contract via selfDestruct meaning nobody can withdraw
        require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
        uint256 feesToWithdraw = totalFees;
        totalFees = 0;
        //q - what if the feeAddress is a smart contract with a fallback that will fail? For the purposes of this audit, lets assume that the feeAdress is always trusted and working
        //slither-disable-next-line arbitrary-send-eth
        (bool success,) = feeAddress.call{value: feesToWithdraw}("");
        require(success, "PuppyRaffle: Failed to withdraw fees");
    }

    /// @notice only the owner of the contract can change the feeAddress
    /// @param newFeeAddress the new address to send fees to
    function changeFeeAddress(address newFeeAddress) external onlyOwner {
        //@report-written check for zero address, input validation
        feeAddress = newFeeAddress;
        //@report-written - are we missing events in other functions?
        emit FeeAddressChanged(newFeeAddress);
    }

    /// @notice this function will return true if the msg.sender is an active player
    // @report-written - this isn't used anywaywhere, is it necessary?
    function _isActivePlayer() internal view returns (bool) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == msg.sender) {
                return true;
            }
        }
        return false;
    }

    /// @notice this could be a constant variable
    function _baseURI() internal pure returns (string memory) {
        return "data:application/json;base64,";
    }

    /// @notice this function will return the URI for the token
    /// @param tokenId the Id of the NFT
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "PuppyRaffle: URI query for nonexistent token");

        uint256 rarity = tokenIdToRarity[tokenId];
        string memory imageURI = rarityToUri[rarity];
        string memory rareName = rarityToName[rarity];

        return string(
            abi.encodePacked(
                _baseURI(),
                Base64.encode(
                    bytes(
                        abi.encodePacked(
                            '{"name":"',
                            name(),
                            '", "description":"An adorable puppy!", ',
                            '"attributes": [{"trait_type": "rarity", "value": ',
                            rareName,
                            '}], "image":"',
                            imageURI,
                            '"}'
                        )
                    )
                )
            )
        );
    }
}
