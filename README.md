# Freehold

>  /ˈfrēˌhōld/
>  
> _noun_
>  
>  : permanent and absolute tenure of land or property with freedom to dispose of it at will.

Freehold is a library to help users gain freehold of their data, using in-browser cryptography coupled with the power of popular crpyto wallets. 

### Install

```
$ npm install --save-dev freehold
```

### Usage

Freehold can be used in both the browser as well as Node. For this usage example, we'll assume a typscript/ES6 integration with the proper preprocessing (which can apply to both):
 
```typescript
// Assume provider and signer are properly initialized per ethers documentation
let provider:ethers.providers.JsonRpcProvider = /* ... */; 
let signer:ethers.providers.JsonRpcSigner = /* ... */;

// Address that will respond to personal_sign requests
let address = signer.getAddress();

// Define the user-provided data to be signed by the crypto wallet.
// Two types are available: "password" and "message", and are handled
// differently. See below. 
let params:SignatureFragment = {
  type: "password",
  data: "r3a11y5tr0ngpa55w0rd!!!" // user provided
};

// Create a freehold signing object. This will cause the crypto
// wallet to sign the signature fragment(s) via a personal_sign request.
// The params object can be an array of signature fragments.
// Each fragment will trigger a new personal_sign request.
let freeholdSigner = await freehold(
  provider,
  address, 
  params
);

// To encrypt a message:
let message = "I've got a secret...";
let ciphertext = freeholdSigner.encrypt(message)
// => "uzhmDmK5NKaZ-yQvSmhrHJw3rcfvPblE-sKsNZiK10-9L72NZzARrRBAp6L60hSA"

// To decrypt:
let decryptedMessage = freeholdSigner.decrypt(ciphertext);
// => "I've got a secret...".
  
```

### Possible attacks

Freehold helps app developers secure their user's data (even from themselves!), but freehold can't help with all types of attacks. Here's a non-exhaustive list of attack types and how freehold can help:

* Malicious access to password, or password leaked through external means and used to decrypt sensitive data
  * ✔️ Protected: Signatures from the crypto wallet are used in key generation, and the deterministic signing key cannot be created by the password alone. An attacker would also need access to the crypto wallet in order to decrypt sensitive data, and when used with a hardware wallet, this would require physical access.
* Malicious wallet application, or MiM attack during production of wallet signatures in order to decrypt sensitive data
  * ✔️ Protected: The user's password is part of key generation, and the deterministic signing key cannot be created by the wallet signature alone. An attacker would also need access to the password to decrypt sensitive data. Note that the plaintext password is never sent to the wallet; instead, it is hashed and then quickly disposed of before being used in the key generation and signing process.
* Key derivation through malicious access and analysis of encrypted data (e.g., rainbow table attacks, brute forcing, quirks of encryption schemes, etc.):
  * ✔️ Protected: Freehold uses two types of encryption to encrypt users' data. First, a master key is created using PBKDF2 from a mixture of both the user's password as well as signature fragments from the crypto wallet. Then, for each encryption request, Freehold runs a random salt through 100k PBKDF2 iterations (the same amount as 1Password) to create a seed for the next encryption step. Finally, Freehold uses 256-bit AES-GCM encryption with a random 96-bit initialization value to encrypt the data (if you're a crypto nut, this all means something). Together, this dual ecryption scheme protects against brute-force attacks by requiring attackers to run computationally-expensive PBKDF2 iterations on every brute-force attempt, which they'd be silly to do. And by using the salted PBKDF2 result as a seed into the AES-GCM encryption algorithm, we gain all the security benefits of AES-GCM encryption while completely bypassing its rough edges (which are, specifically, that using the same key and same IV more than once during encryption could allow attackers to uncover the secret key through careful analysis). Here we ensure every encryption request has a completely unique key (e.g., PBKDF2 + random salt + AES == key), that will never overlap with any other. And even if the key for a specific piece of data is discovered, only that piece of data is at risk, rather than the whole data set. Additionally, all encryption algorithms mentioned are supplied natively by the browser, rather than provided by Freehold, which maintains the trust assumptions users already possess. 
* Supply chain attack on application source code, maliciously altering code to A) transmit cleartext data to a third party (or the application author) after it's decrypted; B) spoof wallet interactions; C) do anything malicious.
  * ❌ Not protected: The application needs to be trusted, as ultimately the application is managing the encryption and decryption process (and the protection of encrypted vs. cleartext data). These risks can be mitigated by open-sourcing frontend code, conducting security audits, implementing [Hardened Javascript](https://agoric.com/wp-content/uploads/2021/10/Hardened-JavaScript.pdf), and placing audited and trusted frontend code in content-addressable storage like [IPFS](https://ipfs.io/) so you know it's not tampered with. 

### TODO

* Random-order fragment signing so malicious wallet or MiM can't detect order. Only viable in cases with a large number of fragments (not likely). Perhaps we can sign all the fragments once in a randomized order? (Alternatively, randomly sign signatures that won't be used to fool the wallet.)