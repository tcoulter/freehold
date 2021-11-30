import { hexlify } from '@ethersproject/bytes';
import { toUtf8Bytes } from '@ethersproject/strings';
import { SiweMessage } from 'siwe';
import * as secp from "@noble/secp256k1";
import utils from "ethereumjs-utils";


import { 
  ethers 
} from 'ethers';
import webcrypto from "webcrypto-liner";

let crypto:typeof webcrypto.nativeCrypto;

if (typeof webcrypto === "undefined") {
  crypto = require("crypto").webcrypto;
}

let doc;

if (typeof document !== "undefined") {
  doc = document;
} else {
  doc = {
    location: {
      host: "localhost",
      origin: "http://localhost"
    }
  }
}


export type SignatureType = "message" | "password";

export type SignatureFragment = {
  data: string,
  type: SignatureType
}

type EncryptMethod = (plaintext:string) => Promise<string>;
type DecryptMethod = (cipherText:string) => Promise<string>;

class FreeholdSigner {
  private _encrypt:EncryptMethod;
  private _decrypt:DecryptMethod;

  constructor(
    encrypt: EncryptMethod,
    decrypt: DecryptMethod  
  ) {
    this._encrypt = encrypt;
    this._decrypt = decrypt;
  }

  async encrypt(plaintext:string) {
    return this._encrypt(plaintext);
  }

  async decrypt(cipherText:string) {
    return this._decrypt(cipherText);
  }
}

type SignerParams = {
  password: string;
  signature: string;
  message: string
}

async function __createSigner(
  {
    password,
    signature,
    message
  }:SignerParams
) {         
  let enc = new TextEncoder();
  let seed = enc.encode(password);

  // Create the initial key material for PBKDF2 derivation
  let masterKey = await crypto.subtle.importKey(
    "raw",
    seed,
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  ) 

  // Now, recover the user's EC public key from message signature
  const msgHash = ethers.utils.hashMessage(message)
  const msgHashBytes = Buffer.from(msgHash.replace("0x", ""), "hex");

  let userPublicKey = ethers.utils.recoverPublicKey(msgHashBytes, signature);

  // This sensitive info is no longer needed. Signal we don't want it
  // and get it out of scope.
  password = undefined;
  signature = undefined;
  message = undefined;


  return new FreeholdSigner(
    async (plaintext:string) => {
      // Generate a random 96-bit IV for use in encryption/decryption
      // and a 128-bit salt. 
      const iv = crypto.getRandomValues(new Uint8Array(12));                            
      const pbkdf2salt = crypto.getRandomValues(new Uint8Array(16));
      const hkdfsalt = crypto.getRandomValues(new Uint8Array(16));  

      // Create a PBKDF2 key based on the salt and the master key
      let rawPbkdf2Bits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: pbkdf2salt,
          iterations: 100000,
          hash: "SHA-256"
        },
        masterKey,
        256
      )

      let sharedSecretKey = await crypto.subtle.importKey(
        "raw",
        Buffer.from(secp.getSharedSecret(new Uint8Array(rawPbkdf2Bits), userPublicKey.replace("0x", ""))),
        {name: "HKDF"},
        false, 
        ["deriveBits", "deriveKey"]
      )

      let derivedKey = await crypto.subtle.deriveKey(
        {
          name: "HKDF", 
          hash: "SHA-256", 
          salt: hkdfsalt,
          info: new Uint8Array([])
        },
        sharedSecretKey,
        {
          name: "AES-GCM",
          length: 256
        }, 
        false,
        ["encrypt"]
      )

      // Encrypt the plaintext via AES using the key and the iv
      const ct = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        derivedKey,
        enc.encode(plaintext)
      )

      // Convert result to buffer
      const ctBuffer = Buffer.from(ct);                             
     
      // Return a base64url encoded string that includes both the iv, salt, and
      // cipher text. This makes the data easy to store and pass around.
      return Buffer.concat([
        iv,
        pbkdf2salt,
        hkdfsalt,
        ctBuffer
      ]).toString("base64url");
    },
    async (cipherText:string) => {
      // Convert from base64url to buffer
      const data = Buffer.from(cipherText, "base64url");

      // Grab the iv and salt from the beginning of the data buffer
      const iv = data.subarray(0, 12);  
      const pbkdf2salt = data.subarray(12, 28);
      const hkdfsalt = data.subarray(28, 44)                          

      // Create a PBKDF2 key based on the salt and the master key
      let rawPbkdf2Bits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: pbkdf2salt,
          iterations: 100000,
          hash: "SHA-256"
        },
        masterKey,
        256
      )

      let ecSharedSecret = secp.getSharedSecret(new Uint8Array(rawPbkdf2Bits), userPublicKey.replace("0x", ""))

      let sharedSecretKey = await crypto.subtle.importKey(
        "raw",
        Buffer.from(ecSharedSecret),
        {name: "HKDF"},
        false, 
        ["deriveBits", "deriveKey"]
      )

      let derivedKey = await crypto.subtle.deriveKey(
        {
          name: "HKDF", 
          hash: "SHA-256", 
          salt: hkdfsalt,
          info: new Uint8Array([])
        },
        sharedSecretKey,
        {
          name: "AES-GCM",
          length: 256
        }, 
        false,
        ["decrypt"]
      )
  
      // Get the remaining bytes of the cipher text as the encrypted data
      const ciphertext = data.subarray(44);

      try {
        // Decrypt the cipher text using the key.
        const plainBuffer = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv },
          derivedKey,
          ciphertext
        )
        
        // And convert back to string.
        return new TextDecoder().decode(plainBuffer);                                                                                   
      } catch (e) {
        throw new Error('Decrypt failed: ' + typeof e.message !== "undefined" ? e.message : e);
      }
    }
  )
}

export type FreeholdConstructor = {
  password: string,
  provider: ethers.providers.JsonRpcProvider,
  address: string, 
  domain: string,
  uri: string,
  statement: string
}

export default async function freehold({
  password,
  provider,
  address,
  domain = doc.location.host,
  uri = doc.location.origin,
  statement = ""
}) {
  let nonce = Buffer.from(crypto.getRandomValues(new Uint8Array(6))).toString("base64url");
  let chainId:number = await provider.getNetwork().then(({ chainId }) => chainId);

  const message = new SiweMessage({
    domain,
    address,
    chainId: `${chainId}`,
    uri,
    version: '1',
    statement,
    nonce,
  });

  let rawMessage = message.signMessage();
  const signature = await provider.getSigner().signMessage(rawMessage);

  return __createSigner({
    password, 
    signature,
    message: rawMessage
  });
}