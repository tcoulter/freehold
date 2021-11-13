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

function generateAesGcmIv() {
  // Notice here that we're creating a 12-byte random
  // initialization vector. AES-GCM doesn't require the
  // IV to be random, only that it be unique. Using a
  // random value does increase the incidence of the 
  // birthday problem, although it is very rare. 
  // Because we're using a random value as the IV,
  // this library is limited to ecrypting about
  // 4 billion messages before becoming unsafe. 
  // 
  // Note that encrypting any two messages with the same
  // IV and the same key could cause the key to be exposed.
  // More discussion at the following links: 
  // 
  // https://crypto.stackexchange.com/questions/58329/can-aes-gcm-be-broken-if-initialisation-vector-is-known
  // https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams

  return crypto.getRandomValues(new Uint8Array(12));
}

// Define a very small scope that holds the full secretKey
async function __createSignerObject(secretKey:string) {

  // Hash the secret key immediately, and remove the raw version.
  const secretHash = await crypto.subtle.digest(
    'SHA-256', 
    new TextEncoder().encode(secretKey)
  );         

  // Just for good measure. Keep the raw data out of scope.
  secretKey = undefined;

  // Structure of this encryption scheme taken from here: 
  // https://gist.github.com/chrisveness/43bcda93af9f646d083fad678071b90a

  let enc = new TextEncoder();

  return new FreeholdSigner(
    async (plaintext:string) => {
      // Generate a random 96-bit IV for use in encryption/decryption
      // See comments in generateAesGcmIv() function for security implications.
      const iv = generateAesGcmIv()                             
      const algorithm = { name: 'AES-GCM', iv: iv };      
      
      // Create a crypto key based on the secret passed in
      const key = await crypto.subtle.importKey(
        'raw', 
        secretHash, 
        algorithm, 
        false, 
        ['encrypt']
      ); 

      // Encode the string and encrypt it using the 
      const ptUint8 = new TextEncoder().encode(plaintext);                               
      const ct = await crypto.subtle.encrypt(algorithm, key, ptUint8);                  

      // Convert result to buffer
      const ctBuffer = Buffer.from(ct);                             
     
      // Return a base64 encoded string that includes both the iv as well
      // as the cipher text. This makes the data easy to store and pass around.
      return Buffer.concat([
        iv,
        ctBuffer
      ]).toString("base64");
    },
    async (cipherText:string) => {
      // Convert from base64 to buffer
      const data = Buffer.from(cipherText, "base64");

      // The first 12 bytes are the IV
      const iv = data.subarray(0, 12);  

      // Recreate the crypto key based on secret passed in
      const algorithm = { name: 'AES-GCM', iv: iv };                                           
      const key = await crypto.subtle.importKey(
        'raw', 
        secretHash,
        algorithm, 
        false, 
        ['decrypt']
      ); 
  
      // Get the remaining bytes of the cipher text as the encrypted data
      const ct = data.subarray(12);

      try {
        // Decrypt the cipher text using the key.
        const plainBuffer = await crypto.subtle.decrypt(algorithm, key, ct);
        
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