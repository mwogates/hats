import { ethers } from "ethers";
import { useEffect, useState } from "react";

const useENS = (address) => {
  const [ensName, setENSName] = useState();

  useEffect(() => {
    const resolveENS = async () => {
      if (address && ethers.utils.isAddress(address)) {
        const provider = ethers.providers.getDefaultProvider();
        const ensName = await provider.lookupAddress(address);
        setENSName(ensName);
      }
    };
    resolveENS();
  }, [address]);

  return { ensName };
};

export default useENS;
