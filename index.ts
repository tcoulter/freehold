import { hexlify } from '@ethersproject/bytes';
import { toUtf8Bytes } from '@ethersproject/strings';

import { 
  ethers 
} from 'ethers';
import webcrypto from "webcrypto-liner";

let crypto:typeof webcrypto.nativeCrypto;

if (typeof webcrypto === "undefined") {
  crypto = require("crypto").webcrypto;
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

async function __createSignerObject(secretKey:string) {         
  // Structure of this encryption is a mixture of the following two resources: 
  // https://gist.github.com/chrisveness/43bcda93af9f646d083fad678071b90a
  // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey#pbkdf2_2

  let enc = new TextEncoder();

  let seed = Buffer.concat([
    enc.encode(secretKey),
    //crypto.getRandomValues(new Uint8Array(16))
  ]) 

  let masterKey = await crypto.subtle.importKey(
    "raw",
    seed,
    "PBKDF2",
    false,
    ["deriveBits", "deriveKey"]
  ) 

  // Just for good measure. Keep the raw data out of scope.
  secretKey = undefined;

  return new FreeholdSigner(
    async (plaintext:string) => {
      // Generate a random 96-bit IV for use in encryption/decryption
      // and a 128-bit salt. 
      const iv = crypto.getRandomValues(new Uint8Array(12));                            
      const salt = crypto.getRandomValues(new Uint8Array(16));  

      // Create a PBKDF2 key based on the salt and the master key
      let key = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: 100000,
          hash: "SHA-256"
        },
        masterKey,
        {name: "AES-GCM", length: 256},
        false,
        ["encrypt"]
      )

      // Encrypt the plaintext via AES using the key and the iv
      const ct = await crypto.subtle.encrypt(
        {
          name: "AES-GCM",
          iv: iv
        },
        key,
        enc.encode(plaintext)
      )

      // Convert result to buffer
      const ctBuffer = Buffer.from(ct);                             
     
      // Return a base64url encoded string that includes both the iv, salt, and
      // cipher text. This makes the data easy to store and pass around.
      return Buffer.concat([
        iv,
        salt,
        ctBuffer
      ]).toString("base64url");
    },
    async (cipherText:string) => {
      // Convert from base64url to buffer
      const data = Buffer.from(cipherText, "base64url");

      // Grab the iv and salt from the beginning of the data buffer
      const iv = data.subarray(0, 12);  
      const salt = data.subarray(12, 28);                          

      // Recreate the deterministic key from the salt and the master key
      let key = await crypto.subtle.deriveKey(
        {
          name: "PBKDF2",
          salt: salt,
          iterations: 100000,
          hash: "SHA-256"
        },
        masterKey,
        {name: "AES-GCM", length: 256},
        false,
        ["decrypt"]
      )
  
      // Get the remaining bytes of the cipher text as the encrypted data
      const ciphertext = data.subarray(28);

      try {
        // Decrypt the cipher text using the key.
        const plainBuffer = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv },
          key,
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

async function __createSigner(
  provider:ethers.providers.JsonRpcProvider, 
  address:string,
  fragmentData:string):Promise<FreeholdSigner> 
{
  return (async () => {
    // Create a deep copy, and let's get rid of the original object
    let toSign:SignatureFragment | Array<SignatureFragment> = JSON.parse(fragmentData);

    // Make sure it's an array
    if (!Array.isArray(toSign)) {
      toSign = [toSign];
    }

    // For all password fragments, hash the password and ditch the actual password data
    for (let fragment of toSign) {
      if (fragment.type == "password") {
        fragment.data = Buffer.from(await crypto.subtle.digest(
          'SHA-256', 
          new TextEncoder().encode(fragment.data)
        )).toString("hex");      
      }
    } 

    // We try really hard to leave as little data at rest as possible
    // e.g., we don't store signed messages in memory for very long
    return __createSignerObject(
      await toSign.map<Promise<[SignatureFragment, string]>>(async (fragment) => {
        return [
          fragment, 
          (await provider.send('personal_sign', 
            [
              hexlify(toUtf8Bytes(fragment.data)), 
              address
            ]
          )).replace("0x", "")
        ];
      }).reduce(async (key, tuple) => {
        // Add on the unsigned data + signature for this fragment.
        return (await key) + (await tuple)[1] + (await tuple)[0].data;
      }, Promise.resolve(""))
    )
  })();
};

export default async function freehold(
  provider:ethers.providers.JsonRpcProvider,
  address:string,
  toSign:SignatureFragment | Array<SignatureFragment>
) {
  // We call a private signer just to be extra careful.
  // We stringify the input becasue we don't want to hold a 
  // a reference to the original data.
  return __createSigner(provider, address, JSON.stringify(toSign));
}