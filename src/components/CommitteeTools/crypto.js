export async function generateKey(passphrase: string | undefined): Promise<[string, string]> {
    const keypair = await crypto.subtle.generateKey(keyParams, true, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey'])

    const privateKey = await crypto.subtle.exportKey("pkcs8", keypair.privateKey!)
    const publicKey = await crypto.subtle.exportKey("spki", keypair.publicKey!)

    if (passphrase && passphrase !== "") {
        wrapCryptoKey(keypair.privateKey, passphrase)
    }

    return [arrayBufferToBase64String(privateKey), arrayBufferToBase64String(publicKey)]
}

const keyParams = {
    name: "RSA-OAEP",
    // Consider using a 4096-bit key for systems that require long-term security
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
}

export async function decrypt(privateKey: CryptoKey, message: string): Promise<string | undefined> {
    const buffer = new TextEncoder().encode(message)
    const decrypted = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, privateKey, buffer)
    return new TextDecoder().decode(decrypted)
}

export async function encrypt(publicKey: CryptoKey, message: string): Promise<string | undefined> {
    const buffer = new TextEncoder().encode(message)
    const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, buffer)
    return new TextDecoder().decode(encrypted)
}

async function importPrivateKey(privateKeyBase64): Promise<CryptoKey | undefined> {
    console.log("importing key ", privateKeyBase64)
    const privateKey = base64StringToArrayBuffer(privateKeyBase64)
    console.log("buffer ", privateKey)
    return await crypto.subtle.importKey("pkcs8", privateKey, keyParams, true, ['decrypt'])
}

async function importPublicKey(privateKeyBase64): Promise<CryptoKey | undefined> {
    console.log("importing key ", privateKeyBase64)
    const privateKey = base64StringToArrayBuffer(privateKeyBase64)
    console.log("buffer ", privateKey)
    return await crypto.subtle.importKey("spki", privateKey, keyParams, true, ['encrypt'])
}

export async function readPrivateKeyFromStoredKey({ passphrase, privateKey }: IStoredKey) {
    return importPrivateKey(privateKey)
}
export async function readPublicKeyFromStoredKey({ privateKey }: IStoredKey) {
    return importPublicKey(privateKey)
}

async function getKeyMaterial(passphrase) {
    const enc = new TextEncoder();
    return window.crypto.subtle.importKey(
        "raw",
        enc.encode(passphrase),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
}

function getWrappingKey(keyMaterial, salt) {
    return window.crypto.subtle.deriveKey(
        {
            "name": "PBKDF2",
            salt: salt,
            "iterations": 100000,
            "hash": "SHA-256"
        },
        keyMaterial,
        { "name": "AES-KW", "length": 256 },
        true,
        ["wrapKey", "unwrapKey"]
    );
}

async function wrapCryptoKey(keyToWrap, passphrase) {
    console.log("wrapping key")
    // get the key encryption key
    const keyMaterial = await getKeyMaterial(passphrase);
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const wrappingKey = await getWrappingKey(keyMaterial, salt);

    const wrapped = await window.crypto.subtle.wrapKey(
        "raw",
        keyToWrap,
        wrappingKey,
        "AES-KW"
    );
    console.log({ wrapped })
    //const wrappedKeyBuffer = new Uint8Array(wrapped);
}

function arrayBufferToBase64String(arrayBuffer) {
    var byteArray = new Uint8Array(arrayBuffer)
    var byteString = ''
    for (var i = 0; i < byteArray.byteLength; i++) {
        byteString += String.fromCharCode(byteArray[i])
    }
    return btoa(byteString)
}

function base64StringToArrayBuffer(b64str) {
    var byteStr = atob(b64str)
    var bytes = new Uint8Array(byteStr.length)
    for (var i = 0; i < byteStr.length; i++) {
        bytes[i] = byteStr.charCodeAt(i)
    }
    return bytes.buffer
}