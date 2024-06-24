---
sponsor: "Panoptic"
slug: "2024-06-panoptic"
date: "2024-06-24"
title: "Panoptic"
findings: "https://github.com/code-423n4/2024-06-panoptic-findings/issues"
contest: 387
---

# Overview

## About C4

Code4rena (C4) is an open organization consisting of security researchers, auditors, developers, and individuals with domain expertise in smart contracts.

A C4 audit is an event in which community participants, referred to as Wardens, review, audit, or analyze smart contract logic in exchange for a bounty provided by sponsoring projects.

During the audit outlined in this document, C4 conducted an analysis of the Panoptic smart contract system written in Solidity. The audit took place between June 4—June 10 2024, as a follow-up focusing on modifications implemented after [Panoptic's April 2024 C4 audit](https://code4rena.com/audits/2024-04-panoptic).

## Wardens

Among the 19 wardens who contributed to this Panoptic audit, the judge found merit in the following wardens' reports:

  1. [sammy](https://code4rena.com/@sammy)
  2. [bigtone](https://code4rena.com/@bigtone)
  3. [Bauchibred](https://code4rena.com/@Bauchibred)

This audit was judged by [Picodes](https://code4rena.com/@Picodes).

Final report assembled by [liveactionllama](https://twitter.com/liveactionllama).

# Summary

The C4 analysis yielded 0 vulnerabilities with a risk rating in the categories of HIGH severity or MEDIUM severity.

Additionally, C4 analysis included 3 reports detailing issues with a risk rating of LOW severity or non-critical.

All of the issues presented here are linked back to their original finding.

# Scope

The code under review can be found within the [C4 Panoptic repository](https://github.com/code-423n4/2024-06-panoptic), and is composed of 1 interface and 21 smart contracts written in the Solidity programming language and includes 5,119 lines of Solidity code.

# Severity Criteria

C4 assesses the severity of disclosed vulnerabilities based on three primary risk categories: high, medium, and low/non-critical.

High-level considerations for vulnerabilities span the following key areas when conducting assessments:

- Malicious Input Handling
- Escalation of privileges
- Arithmetic
- Gas use

For more information regarding the severity criteria referenced throughout the submission review process, please refer to the documentation provided on [the C4 website](https://code4rena.com), specifically our section on [Severity Categorization](https://docs.code4rena.com/awarding/judging-criteria/severity-categorization).

# Low Risk and Non-Critical Issues

For this audit, 3 reports were submitted by wardens detailing low risk and non-critical issues. The [report highlighted below](https://github.com/code-423n4/2024-06-panoptic-findings/issues/38) by **sammy** received the top score from the judge.

*The following wardens also submitted reports: [bigtone](https://github.com/code-423n4/2024-06-panoptic-findings/issues/30) and [Bauchibred](https://github.com/code-423n4/2024-06-panoptic-findings/issues/26).*

## `s_poolAssets` underflow in `CollateralTracker.sol` will lead to protocol failure

`s_poolAssets` can underflow in `CollateralTracker.sol`. This is because, in the `withdraw()` function, the assets that the user withdraws are deducted from `s_poolAssets`; however, there is no check to ensure `s_poolAssets >= assets`. Moreover, the updation of `s_poolAssets` is handled in an unchecked block, which makes the underflow possible.

```solidity
    function withdraw(
        uint256 assets,
        address receiver,
        address owner,
        TokenId[] calldata positionIdList
    ) external returns (uint256 shares) {
        shares = previewWithdraw(assets);


        // check/update allowance for approved withdraw
        if (msg.sender != owner) {
            uint256 allowed = allowance[owner][msg.sender]; // Saves gas for limited approvals.


            if (allowed != type(uint256).max) allowance[owner][msg.sender] = allowed - shares;
        }


        // burn collateral shares of the Panoptic Pool funds (this ERC20 token)
        _burn(owner, shares);


        // update tracked asset balance
        unchecked {
            s_poolAssets -= uint128(assets);
        }


        // reverts if account is not solvent/eligible to withdraw
        s_panopticPool.validateCollateralWithdrawable(owner, positionIdList);


        // transfer assets (underlying token funds) from the PanopticPool to the LP
        SafeTransferLib.safeTransferFrom(
            s_underlyingToken,
            address(s_panopticPool),
            receiver,
            assets
        );


        emit Withdraw(msg.sender, receiver, owner, assets, shares);


        return shares;
    }
```

`s_poolAssets` can be less than `assets`, this is because when a short option is minted, assets are moved from the Panoptic pool to the Uniswap pool. i.e, assets are deducted from `s_poolAssets` and incremented in `s_inAMM`.

So, the underflow is possible when a large share of the deposited liquidity is in the Uniswap pool.

### Impact

This breaks the functionality and accounting of the entire protocol. A number of attacks can be performed to drain the pool due to this vulnerability. An example would be:

1.  Attacker mints a large number of short options.
2.  Attacker withdraws and causes underflow.
3.  Attacker can drain the pool by calling `withdraw()` again as assets are now highly undervalued relative to shares.

### Proof of Concept

The following test demonstrates the underflow scenario :

```solidity
function test_POC_Underflow() public {
        // initalize world state
        uint256 x = 4532 ; uint104 assets = 1000;
        _initWorld(x);
 
        // Invoke all interactions with the Collateral Tracker from user Bob
        vm.startPrank(Bob);
 
        // give Bob the max amount of tokens
        _grantTokens(Bob);
 
        // approve collateral tracker to move tokens on the msg.senders behalf
        IERC20Partial(token0).approve(address(collateralToken0), assets);
 
        // deposit a number of assets determined via fuzzing
        // equal deposits for both collateral token pairs for testing purposes
        uint256 returnedShares0 = collateralToken0.deposit(assets, Bob);
 
        // total amount of shares before withdrawal
 
        uint256 assetsToken0 = convertToAssets(returnedShares0, collateralToken0);
        
        // user mints options and liquidity is moved to the Uniswap pool
        // for simpicity, we manually set the values of `s_poolAssets` and `s_inAMM`
        collateralToken0.setPoolAssets(1);
        collateralToken0.setInAMM(int128(uint128(assets)-1));
 
        // withdraw tokens
        collateralToken0.withdraw(assetsToken0, Bob, Bob, new TokenId[](0));

        // confirm the underflow
        assertEq(collateralToken0._availableAssets(), type(uint128).max - assetsToken0 + 2);
    }
```

To run the test:

1.  Copy the code above into `CollateralTracker.t.sol`
2.  Run `forge test --match-test test_POC_Underflow`

### Tools Used

Foundry

### Recommended Mitigation Steps

Remove the unchecked block.

Alternatively, add this check in `withdraw()`:

```solidity
        if (assets > s_poolAssets) revert Errors.ExceedsMaximumRedemption();
```

### Assessed type

Under/Overflow

**[Picodes (judge) decreased severity to Low/Non-Critical and commented](https://github.com/code-423n4/2024-06-panoptic-findings/issues/38#issuecomment-2166425998):**
 > This is correct but what would be the impact? It seems that `totalAssets` would behave correctly so funds wouldn't be affected. However for example `getPoolData` and `maxWithdraw` would be affected so we could argue that functionality is broken but it isn't described by these reports.
> 
> I'll downgrade to QA.

**[dyedm1 (Panoptic) commented](https://github.com/code-423n4/2024-06-panoptic-findings/issues/38#issuecomment-2166918861):**
 > Can confirm the PoC is valid, but we are also unable to find significant impact on our end (besides some potential confusion if frontends use the values returned by `getPoolData` to display stats).

**[sammy (warden) commented](https://github.com/code-423n4/2024-06-panoptic-findings/issues/38#issuecomment-2176681896):**
 > Agreed that the impact isn't correctly described in the report. Kudos to the judge @Picodes for pointing it out. However, the following problems still occur:
> 
> 1.  `maxWithdraw()` will return the incorrect amount, which will lead to reverts for the `withdraw()` function temporarily. This is a violation of ERC-4626
> 
> 2. `maxRedeem()` will also cause 'redeem' to revert, if the user's shares balance in assets is greater than the pool's token balance. This is, again, a violation of ERC-4626.
> 
> `withdraw()` and `redeem()` will hence be temporarily affected, and some users will also lose access to their funds temporarily. After the pool recovers its balance again through deposits, these functions will operate normally.
> 
> Again, as the judge pointed out, there are no funds directly at risk, which is why my initial conviction that this is a High severity issue is incorrect.
> 
> However, given broken functionality, temporary loss of access to funds, and violations of ERC-4626, I would like to urge the judge to re-assess and see if this should be a `Medium` rather than a `QA`.
> 
> Thanks!

**[Picodes (judge) commented](https://github.com/code-423n4/2024-06-panoptic-findings/issues/38#issuecomment-2177969959):**
 > @sammy - My view is that this issue could have been a Medium but when judging a report we're supposed to take into account only the impacts described by this report, and in this case there is none.



***

# Disclosures

C4 is an open organization governed by participants in the community.

C4 audits incentivize the discovery of exploits, vulnerabilities, and bugs in smart contracts. Security researchers are rewarded at an increasing rate for finding higher-risk issues. Audit submissions are judged by a knowledgeable security researcher and solidity developer and disclosed to sponsoring developers. C4 does not conduct formal verification regarding the provided code but instead provides final verification.

C4 does not provide any guarantee or warranty regarding the security of this project. All smart contract software should be used at the sole risk and responsibility of users.
