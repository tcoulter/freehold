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

Freehold can be used in both the browser as well as Node. For this usage example, we'll assume a typscript/ES6 integration with the proper preprocessing:
 
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

Freehold helps app developers secure thier user's data (even from themselves!), but freehold can't help with all types of attacks. Here's a non-exhaustive list of attack types and how freehold can help:

* Malicious access to password, or password leaked through external means and used to decrypt sensitive data
  * ✔️ Protected: Signatures from the crypto wallet are used in key generation, and the deterministic signing key cannot be created by the password alone. An attacker would also need access to the crypto wallet in order to decrypt sensitive data.
* Malicious wallet, or MiM attack during production of wallet signatures in order to decrypt sensitive data
  * ✔️ Protected: The user's password is part of key generation, and the deterministic signing key cannot be created by the wallet signature alone. An attacker would also need access to the password to decrypt sensitive data. Note that the password is never sent to the wallet; instead, it is hashed and then quickly disposed of before being used in the key generation and signing process.
* Key derivation through malicious access and analysis of encrypted data (e.g., encrypted data stored in local storage or session storage):
  * 🟡 Mostly protected: Freehold uses 256-bit AES-GCM encryption with a random 96-bit initialization value, which is considered [extremely safe](https://www.n-able.com/blog/aes-256-encryption-algorithm) if used within the [appropriate limits](https://security.stackexchange.com/questions/202067/how-long-is-key-lifetime-of-aes-gcm-key). This means that per unique signer created with freehold, the maximum number of messages you can encrypt is 2^32 (~4 billion), and the maximum message length is 64GB (yes, gigabytes). After these limits, the security of the encryption scheme is greatly reduced. These limits are more than acceptable for web application data, and so AES-GCM was chosen both for its speed as well as its cross-browser availability. **Do not** use freehold in applications where these limits will be surpassed.
* Supply chain attack on application source code, maliciously altering code to transmit cleartext data to a third party (or the application author) after it's decrypted
  * ❌ Not protected: The application needs to be trusted, as ultimately the application is managing the encryption and decryption process. These risks can be mitigated by open-sourcing frontend code, conducting security audits, implementing [Hardened Javascript](https://agoric.com/wp-content/uploads/2021/10/Hardened-JavaScript.pdf), and placing audited and trusted frontend code in content-addressable storage like [IPFS](https://ipfs.io/) so you know it's not tampered with. 

### TODO

* Random-order fragment signing so malicious wallet or MiM can't detect order. Only viable in cases with a large number of fragments (not likely). Perhaps we can sign all the fragments once in a randomized order? (Alternatively, randomly sign signatures that won't be used to fool the wallet.)