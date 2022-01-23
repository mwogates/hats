import { useRef } from "react"
import { IStoredKey } from "../../types/types"
import { generateKey } from "./util"
import OpenCrypto from 'opencrypto'
const crypt = new OpenCrypto()

export default function NewKey({ addKey }: { addKey: (newKey: IStoredKey) => any }) {
    const aliasRef = useRef<HTMLInputElement>(null)
    const passphraseRef = useRef<HTMLInputElement>(null)


    async function _handleClick() {
        const alias = aliasRef.current!.value
        const passphrase = passphraseRef.current?.value

        const keypair = await crypt.getRSAKeyPair(2048, "SHA-512", "RSA-OAEP", ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'], true) as CryptoKeyPair
        let privateKey
        if (passphrase && passphrase !== "") {
            privateKey = await crypt.encryptPrivateKey(keypair.privateKey!, passphrase, 64000, 'SHA-512', 'AES-GCM', 256)
        } else {
            privateKey = await crypt.cryptoPrivateToPem(keypair.privateKey!)
        }
        console.log({ privateKey })

        console.log({})
        addKey({ alias, privateKey, passphrase })
    }

    return <div>
        <p>Hello committee member</p>
        <p>Please generate private and public PGP keys by creating an alias and a passphrase.</p>
        <p>Alias</p>
        <input ref={aliasRef} type="text" />
        <p>Passphrase</p>
        <p>Please notice,your passphrase isn’t saved to local storage! please save it as you see fit.</p>
        <input ref={passphraseRef} type="text" />

        <p>Min 6 chars</p>
        <button onClick={_handleClick}>Generate key pair </button>

    </div>
}