import OpenCrypto from "opencrypto";
import { useCallback, useEffect, useRef, useState } from "react";
import store from "../../store";
import { IStoredKey } from "../../types/types";
import CopyToClipboard from "../Shared/CopyToClipboard";
import Modal from "../Shared/Modal";
const crypt = new OpenCrypto()

export default function Decrypt({ storedKey }: { storedKey: IStoredKey }) {
    const [privateKey, setPrivateKey] = useState<CryptoKey>()
    const [publicKey, setPublicKey] = useState<CryptoKey>()
    const [error, setError] = useState<string>()
    const [showKeyDetails, setShowKeyDetails] = useState(false)
    const encryptedMessageRef = useRef<HTMLTextAreaElement>(null)
    const decryptedMessageRef = useRef<HTMLTextAreaElement>(null)

    useEffect(() => {
        const getKeys = async () => {
            const privateKey = await privateKeyfromStore(storedKey)
            setPrivateKey(privateKey)
            setPublicKey(await crypt.getPublicKey(privateKey!, {}))
        }
        getKeys()

    }, [])

    useEffect(() => {
        console.log(privateKey)
    }, [privateKey])
    useEffect(() => {
        console.log(publicKey)
    }, [publicKey])

    const _decrypt = useCallback(async () => {
        try {
            const encryptedMessage = encryptedMessageRef.current!.value
            const decrypted = await crypt.rsaDecrypt(privateKey!, encryptedMessage)
            decryptedMessageRef.current!.value = crypt.arrayBufferToString(decrypted)
        } catch (error) {
            if (error instanceof Error) {
                setError(error.message)
            }
        }
    }, [privateKey])

    const _encrypt = useCallback(async () => {
        try {
            const message = decryptedMessageRef.current!.value
            console.log("encrypting using", publicKey!)
            const encrypted = await crypt.rsaEncrypt(publicKey!, new TextEncoder().encode(message))
            console.log({ encrypted })
            encryptedMessageRef.current!.value = encrypted
        } catch (error) {
            if (error instanceof Error) {
                setError(error.message)
            }
        }
    }, [publicKey])

    if (!privateKey) return <></>

    return <div>
        <div>
            <button onClick={() => setShowKeyDetails(true)}>show key details</button>
            {error && <p>{error}</p>}
            {showKeyDetails && <Modal
                title="Key Details"
                setShowModal={setShowKeyDetails}
            >
                <KeyDetails storedKey={storedKey} privateKey={privateKey} />
            </Modal>}
            <p>Encrypted message</p>
            <textarea ref={encryptedMessageRef} cols={80} rows={15} />

            <div><button onClick={_decrypt}>Decrypt</button></div>
            <p>Decrypted message</p>
            <textarea ref={decryptedMessageRef} cols={80} rows={15} />
            <div><button onClick={_encrypt}>Encrypt</button></div>
        </div>
    </div>
}

async function privateKeyfromStore(storedKey: IStoredKey): Promise<CryptoKey> {
    if (storedKey.passphrase && storedKey.passphrase !== "") {
        return await crypt.decryptPrivateKey(storedKey.privateKey, storedKey.passphrase, {})
    } else {
        return await crypt.pemPrivateToCrypto(storedKey.privateKey, {})
    }
}

function KeyDetails({ storedKey, privateKey, publicKey }: {
    storedKey: IStoredKey
    privateKey: CryptoKey
}) {

    useEffect(() => {
        const getPublicKey = async () => {
            const publicKey = await crypt.getPublicKey(privateKey, {})
            const publicKeyPem = await crypt.cryptoPublicToPem(publicKey)
            console.log({ publicKeyPem })
            setPublicKey(publicKeyPem)
        }
        getPublicKey()
    }, [privateKey])

    return <div>
        <p>Private Key<CopyToClipboard value={storedKey.privateKey} /></p>
        <p>Public Key<CopyToClipboard value={publicKey!} /></p>
        {(storedKey.passphrase && storedKey.passphrase !== "") && <p>Passphrase<CopyToClipboard value={storedKey.passphrase} /></p>}
    </div>
}