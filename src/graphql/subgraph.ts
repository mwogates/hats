import { gql } from "apollo-boost";

export const GET_VAULTS = gql`
  {
    vaults {
      id
      pid
      stakingToken
      totalStaking
      totalReward
      totalRewardPaid
      committee
      allocPoint
      master {
        address
        numberOfSubmittedClaims
        withdrawPeriod
        safetyPeriod
        withdrawRequestEnablePeriod
        withdrawRequestPendingPeriod
      }
      numberOfApprovedClaims
      rewardsLevels
      rewardsSplit
      totalRewardAmount
      liquidityPool
      description
      honeyPotBalance
      registered
      withdrawRequests {
        id
        beneficiary
        withdrawEnableTime
        createdAt
        expiryTime
      }
      stakingTokenDecimals
      totalUsersShares
      guests {
        id
        pid
        name
        descriptionHash
        description
        bounty
      }
    }
  }
`;

// rewardsToken is the HAT token
export const GET_MASTER_DATA = gql`
  {
    masters {
      rewardsToken
      withdrawPeriod
      safetyPeriod
    }
  }
`

export const getStakerData = (vaultID: string, stakerAddress: string) => {
  return gql`
    {
      stakers (where: { vault: "${vaultID}", address: "${stakerAddress}" }) {
        shares
        depositAmount
        withdrawAmount
      }
    }
  `;
}

export const getStakerAmounts = (stakerAddress: string) => {
  return gql`
    {
      stakers (where: { address: "${stakerAddress}" }) {
        shares
        depositAmount
        withdrawAmount
        vault {
          stakingToken
        }
      }
    }
  `;
}

export const getBeneficiaryWithdrawRequests = (pid: string, beneficiary: string) => {
  return gql`
    {
      vaults (where: { pid: "${pid}" }) {
        withdrawRequests(where: { beneficiary: "${beneficiary}" }) {
          id
          beneficiary
          withdrawEnableTime
          createdAt
          expiryTime
        }
      }
    }
  `;
}
