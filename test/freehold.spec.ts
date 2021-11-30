import { ethers } from "ethers";
import freehold, { SignatureFragment } from "..";
import expect from "expect";

describe("Freehold", () => {
  let provider:ethers.providers.JsonRpcProvider;
  let signer:ethers.providers.JsonRpcSigner;
  let freeholdSignatureParams:SignatureFragment[] = [
    {
      type: "password",
      data: "asdfadsf"
    }
  ];

  before(async function() {
    provider = new ethers.providers.JsonRpcProvider();
    await provider.ready;

    signer = provider.getSigner();
  })

  describe("encryption/decryption", () => {
    it("encrypts data and can decrypt it", async () => {
      let freeholdSigner = await freehold({
        provider,
        address: await signer.getAddress(), 
        password: "Super secret password!!!"
      });
  
      let message = "Hello from freehold!";
      let cipherText = await freeholdSigner.encrypt(message);
  
      // Make sure we didn't get the message we put in back
      expect(cipherText).not.toBe(message);
  
      let decrypted = await freeholdSigner.decrypt(cipherText);

      console.log(cipherText);
  
      // Make sure we get the message back when decrypting the ciphertext
      expect(decrypted).toBe(message);
    });
  
    it("decrypts data correctly when decrypting data from a different signer instance (think, different sessions)", async () => {
      let freeholdSigner = await freehold({
        provider,
        address: await signer.getAddress(), 
        password: "Super secret password!!!"
      });
  
      let message = "Hello from freehold!";
      let cipherText = await freeholdSigner.encrypt(message);
  
      let newFreeholdSigner = await freehold({
        provider,
        address: await signer.getAddress(),
        password: "Super secret password!!!"
      });
  
      let decrypted = await newFreeholdSigner.decrypt(cipherText);
  
      // Make sure we get the message back when decrypting the ciphertext
      // using a different signer instance
      expect(decrypted).toBe(message);
    })
  
    it("encrypts the same message differently a second time", async () => {
      let freeholdSigner = await freehold({
        provider,
        address: await signer.getAddress(), 
        password: "Super secret password!!!"
      });
  
      let message = "Hello from freehold!";
      let firstCipherText = await freeholdSigner.encrypt(message);
      let secondCipherText = await freeholdSigner.encrypt(message);
  
      expect(firstCipherText).not.toBe(secondCipherText);
    })
  
    it("encrypts the same message differently using a different signer", async () => {
      let firstFreeholdSigner = await freehold({
        provider,
        address: await signer.getAddress(), 
        password: "Super secret password!!!"
      });
  
      let secondFreeholdSigner = await freehold({
        provider,
        address: await signer.getAddress(), 
        password: "Super secret password!!!"
      });
  
      let message = "Hello from freehold!";
      let firstCipherText = await firstFreeholdSigner.encrypt(message);
      let secondCipherText = await secondFreeholdSigner.encrypt(message);
  
      expect(firstCipherText).not.toBe(secondCipherText);
    })
  })
  
  describe("edge cases", () => {

    it("successfully encrypts and decrypts the empty string", async () => {
      let freeholdSigner = await freehold({
        provider,
        address: await signer.getAddress(), 
        password: "Super secret password!!!"
      });
  
      let message = "";

      let cipherText = await freeholdSigner.encrypt(message);
      let decrypted = await freeholdSigner.decrypt(cipherText);
  
      expect(decrypted).toBe(message);
    })
  })
})