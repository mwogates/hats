export interface IParentVault {
  id: string
  pid: string
  stakingToken: string
  stakingTokenDecimals: string
  stakingTokenSymbol: string
  stakers: Array<IStaker>
  totalStaking: string
  honeyPotBalance: string
  totalReward: string
  totalRewardPaid: string
  committee: Array<string>
  allocPoint: string
  master: IMaster
  numberOfApprovedClaims: string
  approvedClaims: Array<IApprovedClaims>
  rewardsLevels: Array<string>
  totalRewardAmount: string
  liquidityPool: boolean
  registered: boolean
  withdrawRequests: Array<IPoolWithdrawRequest>
  totalUsersShares: string
  descriptionHash: string
  guests: Array<IVault>
  hackerVestedRewardSplit: string
  hackerRewardSplit: string
  committeeRewardSplit: string
  swapAndBurnSplit: string
  governanceHatRewardSplit: string
  hackerHatRewardSplit: string
  vestingDuration: string
  vestingPeriods: string
  depositPause: boolean
  committeeCheckedIn: boolean
  apy: number // calculated on the UI - no via subgraph
  tokenPrice: number // calculated on the UI - no via subgraph
}

export interface IVault {
  id: string
  name: string
  descriptionHash: string
  description: IVaultDescription | string
  bounty: string
  isGuest: boolean
  parentDescription: IVaultDescription | string
  parentVault: IParentVault;
}

export interface IVaultDescription {
  "project-metadata": {
    icon: string
    website: string
    name: string
    tokenIcon: string
  }
  "communication-channel": {
    "committee-bot": string
    "pgp-pk": string
  }
  "committee": {
    "multisig-address": string
    "members": Array<ICommitteeMember>
  }
  "severities": Array<ISeverity>
  "source": {
    name: string
    url: string
  }
  message: string
}

export interface ICommitteeMember {
  "name": string
  "address": string
  "twitter-link": string
  "image-ipfs-link"?: string
}

export interface ISeverity {
  "name": string
  "index": number
  "contracts-covered": Array<string>
  "nft-metadata": INFTMetaData
  "reward-for": string
  "description": string
}

export interface INFTMetaData {
  name: string
  description: string
  animation_url: string
  image: string
  external_url: string
}

export interface IStaker {
  id: string
  pid: string
  createdAt: string
  address: string
  parentVault: IParentVault
  rewardPaid: string
  shares: string
  depositAmount: string
  withdrawAmount: string
}

export interface IMaster {
  id: string
  address: string
  governance: string
  totalStaking: string
  totalReward: string
  totalRewardPaid: string
  rewardPerBlock: string
  startBlock: string
  parentVaults: Array<IParentVault>
  totalAllocPoints: string
  createdAt: string
  rewardsToken: string
  numberOfSubmittedClaims: string
  submittedClaim: Array<ISubmittedClaim>
  withdrawPeriod: string
  safetyPeriod: string
  withdrawRequestEnablePeriod: string
  withdrawRequestPendingPeriod: string
  vestingHatDuration: string
  vestingHatPeriods: string
}

export interface ISubmittedClaim {
  id: string
  claim: string
  claimer: string
  createdAt: string
  master: IMaster
}

export interface IApprovedClaims {
  id: string
  approver: string
  parentVault: IParentVault
  beneficiary: string
  sevirity: string
  hackerReward: string
  approverReward: string
  swapAndBurn: string
  hackerHatReward: string
  createdAt: string
}

export interface IPoolWithdrawRequest {
  id: string
  beneficiary: string
  vault: IVault
  withdrawEnableTime: string
  createdAt: string
  expiryTime: string
}

export interface IWithdrawSafetyPeriod {
  isSafetyPeriod: boolean
  saftyStartsAt: number
  saftyEndsAt: number
}
