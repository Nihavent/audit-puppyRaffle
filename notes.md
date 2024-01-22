# About


# High

-Potential DOS attack on unbounded for loop in enterRaffle

-totalFees variable overflows when it exceeds 2^64 due to being a uint64.
-Potential fixes, use uint256, or use a newer version of solidty



# Informational 

`PuppyRaffle:entranceFee` is immutable, better naming convention would be either `i_entranceFee` or `ENTRANCE_FEE`



-Slither / Aderyn
-Code quality/tests