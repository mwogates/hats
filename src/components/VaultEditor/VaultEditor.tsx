import { useEffect, useState } from "react"
import { ICommitteeMember, ISeverity, IVaultDescription } from "types/types"
import { useTranslation } from "react-i18next";
import classNames from "classnames";
import EditableContent from "components/CommitteeTools/components/EditableContent/EditableContent";
import CommmitteeMember from "./CommitteeMember";
import ContractCovered from "./ContractCovered";
import VaultDetails from "./VaultDetails";
import CommunicationChannel from "./CommunicationChannel";
import VaultReview from "./VaultReview";
import VaultSign from "./VaultSign";
import './index.scss'
import { uploadVaultDescription } from "./uploadVaultDescription";
import { getPath, setPath } from "./objectUtils";
import { useLocation } from "react-router-dom";
import { VaultProvider } from "components/CommitteeTools/store";

interface IContract {
    name: string;
    address: string;
    severities: string[];
}

const newMember: ICommitteeMember = {
    name: "",
    address: "",
    "twitter-link": "",
    "image-ipfs-link": ""
}

const newContract: IContract = {
    name: "",
    address: "",
    severities: [],
}

function createSeverity(severity: string): ISeverity {
    return {
        name: severity,
        "contracts-covered": [{ "NEW_CONTRACT": "0x0" }],
        index: 1,
        "nft-metadata": {
            "name": "",
            "description": "",
            "animation_url": "",
            "image": "",
            "external_url": ""
        },
        "reward-for": "",
        "description": ""
    }
}


const newVaultDescription: IVaultDescription = {
    "project-metadata": {
        name: "",
        icon: "",
        tokenIcon: "",
        website: "",
    },
    "communication-channel": {
        "committee-bot": "",
        "pgp-pk": "",
    },
    committee: {
        "multisig-address": "",
        members: [{ ...newMember }]
    },
    severities: ["low", "medium", "high", "critical"].map(createSeverity),
    source: {
        name: "",
        url: ""
    }
}

export default function VaultEditor() {
    const { t } = useTranslation();
    const [vaultDescription, setVaultDescription] = useState<IVaultDescription>(newVaultDescription)
    const [pageNumber, setPageNumber] = useState<number>(1)
    const [contracts, setContracts] = useState({ contracts: [{ ...newContract }] })

    const location = useLocation();

    useEffect(() => {
        const urlSearchParams = new URLSearchParams(location.search);
        const params = Object.fromEntries(urlSearchParams.entries());
        if (params.ipfs) {
            (async () => {
                const response = await fetch(params.ipfs)
                setVaultDescription(await response.json())
            })();
        }
        // convert severities of vault description to contracts state variable
        severitiesToContracts();
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [location.search]);

    // Convert contracts state variable to severities of vault description
    useEffect(() => {
        let severities = ["low", "medium", "high", "critical"].map((severityName) => {
            const filterContracts = contracts.contracts.filter((contract) => {
                return contract.severities.includes(severityName)
            })
            return {
                ...createSeverity(severityName),
                "contracts-covered": filterContracts.map((contract) => ({ [contract.name]: contract.address })),
            }
        })
        setVaultDescription(prev => {
            let newObject = { ...prev }
            setPath(newObject, "severities", severities)
            return newObject
        })
    }, [contracts])


    function onChange(e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) {
        let value
        if (e.target instanceof HTMLInputElement) {
            if (e.target.files && e.target.files.length > 0) {
                value = URL.createObjectURL(e.target.files[0])
            } else {
                value = e.target.value
            }
        } else if (e.target instanceof HTMLTextAreaElement) {
            value = e.target.value
        }

        setVaultDescription(prev => {
            let newObject = { ...prev }
            setPath(newObject, e.target.name, value)
            return newObject
        })
    }

    function removeFromArray(object, path: string, index: number, newItem?: object) {
        let newArray = getPath(object, path)
        newArray.splice(index, 1)
        if (newArray.length < 1 && newItem) newArray = [{ ...(newItem || {}) }]
        let newObject = { ...object }
        setPath(newObject, path, newArray)
        return newObject
    }

    function addMember() {
        setVaultDescription(prev => {
            let newObject = { ...prev }
            setPath(newObject, "committee.members", [...prev.committee.members, { ...newMember }])
            return newObject
        })
    }

    function addPgpKey(pgpKey) {
        setVaultDescription(prev => {
            let newObject = { ...prev }
            const keys = prev["communication-channel"]["pgp-pk"]
            const sureArray = typeof keys === "string" ?
                keys === "" ? [] : [keys] :
                keys
            setPath(newObject, "communication-channel.pgp-pk", [...sureArray, pgpKey])
            return newObject
        })
    }

    function removePgpKey(index: number) {
        const path = "communication-channel.pgp-pk"
        let value = getPath(vaultDescription, path)
        if (typeof value === "string") {
            setVaultDescription(prev => {
                let newObject = { ...prev }
                setPath(newObject, path, "")
                return newObject
            })
        } else {
            let newVaultDescription = removeFromArray(vaultDescription, "communication-channel.pgp-pk", index)
            setVaultDescription(newVaultDescription);
        }
    }

    function removeMember(index: number) {
        let newVaultDescription = removeFromArray(vaultDescription, "committee.members", index, newMember)
        setVaultDescription(newVaultDescription);
    }

    function addContract() {
        setContracts(prev => {
            let newObject = { ...prev }
            setPath(newObject, "contracts", [...prev.contracts, { ...newContract }])
            return newObject
        })
    }

    function removeContract(index: number) {
        let newContracts = removeFromArray(contracts, "contracts", index, newContract)
        setContracts(newContracts);
    }

    function onContractChange(e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) {
        setContracts(prev => {
            let newObject = { ...prev }
            setPath(newObject, e.target.name, e.target.value)
            return newObject
        })
    }

    function severitiesToContracts() {
        let contracts = [] as IContract[];
        vaultDescription.severities.forEach((severity) => {
            const contractsCovered = severity["contracts-covered"];
            contractsCovered.forEach(item => {
                const name = Object.keys(item)[0];
                const address = Object.values(item)[0];
                let contract = contracts.find(item => item.name === name && item.address === address);
                if (contract) {
                    let contractIndex = contracts.indexOf(contract)
                    contracts[contractIndex] = {
                        name,
                        address,
                        severities: [...contract.severities, severity.name]
                    };
                } else {
                    contracts.push({
                        name,
                        address,
                        severities: [severity.name]
                    });
                }
            })
        })
        setContracts({ contracts });
    }

    // Pagination in mobile
    function nextPage() {
        if (pageNumber >= 5) return
        setPageNumber(pageNumber + 1)
        window.scroll({
            top: 0,
            left: 0,
            behavior: 'smooth'
        });
    }

    function previousPage() {
        if (pageNumber <= 1) return
        setPageNumber(oldPage => oldPage - 1)
        window.scroll({
            top: 0,
            left: 0,
            behavior: 'smooth'
        });
    }

    return (
        <div className="content vault-editor">
            <div className="vault-editor__title">
                {t("VaultEditor.create-vault")}
            </div>

            <section className={classNames({ 'desktop-only': pageNumber !== 1 })}>
                <p className="vault-editor__description">
                    {t("VaultEditor.create-vault-description")}
                </p>
                <div className="vault-editor__last-saved-time">
                    {`${t("VaultEditor.last-saved-time")} `}
                    2/14/2022 00:00
                    {`(${t("VaultEditor.local-time")})`}
                </div>

                <div className="vault-editor__section">
                    <p className="vault-editor__section-title">
                        1. {t("VaultEditor.vault-details.title")}
                    </p>
                    <div className="vault-editor__section-content">
                        <VaultDetails
                            projectMetaData={vaultDescription?.["project-metadata"]}
                            onChange={onChange}
                        />
                    </div>
                </div>
            </section>

            <section className={classNames({ 'desktop-only': pageNumber !== 2 })}>
                <div className="vault-editor__section">
                    <p className="vault-editor__section-title">
                        2. {t("VaultEditor.committee-details")}
                    </p>
                    <div className="vault-editor__section-content">
                        <label>{t("VaultEditor.multisig-address")}</label>
                        <EditableContent
                            name="committee.multisig-address"
                            pastable
                            textInput
                            onChange={onChange}
                            placeholder={t("VaultEditor.vault-details.multisig-address-placeholder")} />
                    </div>
                </div>

                <div className="vault-editor__section">
                    <p className="vault-editor__section-title">
                        3. {t("VaultEditor.committee-members")}
                    </p>
                    <div className="vault-editor__section-content">
                        <div className="committee-members">
                            {(vaultDescription?.committee?.members || []).map((member, index) =>
                                <CommmitteeMember
                                    key={index}
                                    member={member}
                                    index={index}
                                    onChange={onChange}
                                    onRemove={removeMember}
                                />)}

                            <button className="fill" onClick={addMember}>
                                {t("VaultEditor.add-member")}
                            </button>
                        </div>
                    </div>
                </div>
            </section>

            <section className={classNames({ 'desktop-only': pageNumber !== 3 })}>
                <div className="vault-editor__section">
                    <p className="vault-editor__section-title">
                        4. {t("VaultEditor.contracts-covered")}
                    </p>
                    <div className="vault-editor__section-content">
                        <div className="contracts-covered">
                            {(contracts.contracts || []).map((contract, index) =>
                                <ContractCovered
                                    key={index}
                                    contract={contract}
                                    index={index}
                                    onChange={onContractChange}
                                    onRemove={removeContract}
                                />)}

                            <button className="fill" onClick={addContract}>
                                {t("VaultEditor.add-member")}
                            </button>
                        </div>
                    </div>
                </div>
            </section>

            <section className={classNames({ 'desktop-only': pageNumber !== 4 })}>
                <div className="vault-editor__section">
                    <p className="vault-editor__section-title">
                        5. {t("VaultEditor.pgp-key")}
                    </p>
                    <div className="vault-editor__section-content">
                        <VaultProvider>
                            <CommunicationChannel
                                removePgpKey={removePgpKey}
                                communicationChannel={vaultDescription?.["communication-channel"]}
                                addPgpKey={addPgpKey}
                                onChange={onChange}
                            />
                        </VaultProvider>
                    </div>
                </div>

                <div className="vault-editor__button-container">
                    <button onClick={() => {
                        uploadVaultDescription(vaultDescription)
                    }} className="fill">{t("VaultEditor.save-button")}</button>
                </div>
            </section>

            <div className="vault-editor__divider desktop-only"></div>

            <section className={classNames({ 'desktop-only': pageNumber !== 5 })}>
                <div className="vault-editor__section">
                    <p className="vault-editor__section-title">
                        6. {t("VaultEditor.review-vault.title")}
                    </p>
                    <div className="vault-editor__section-content">
                        <VaultReview vaultDescription={vaultDescription} />
                        <VaultSign />
                    </div>
                </div>

                <div className="vault-editor__button-container">
                    <button className="fill">{t("VaultEditor.sign-submit")}</button>
                </div>
            </section>

            <div className="vault-editor__next-preview">
                {pageNumber < 5 && (
                    <div>
                        <button className="fill" onClick={nextPage}>{t("VaultEditor.next")}</button>
                    </div>
                )}
                {pageNumber > 1 && (
                    <div>
                        <button onClick={previousPage}>{t("VaultEditor.previous")}</button>
                    </div>
                )}
            </div>
        </div>
    )
}