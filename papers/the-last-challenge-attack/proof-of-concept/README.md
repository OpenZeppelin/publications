# Last Challenge Attack Proof Of Concept

This proof of concept (POC) is a companion to our paper "The Last Challenge Attack: Exploiting the vulnerable Fiat-Shamir transform of a KZG-based SNARK".

The POC forges a proof for an invalid public input chosen by the prover. 
By default, the public input is set to be the hash of the string `"RANDOM_INPUT_SELECTED_BY_THE_PROVER"`.
The public input can be modified, in which case other proofs elements also have to be changed manually. 
Which elements should be changed, as well as how to change them, is explained by comments directly in the code. 

To run the POC, [Foundry](https://book.getfoundry.sh/) should be installed. 

The default forged proof can then be run by executing: 

```
forge test --match-test test_ForgeProof -vvv
```

Note that the verifier implementation in the POC uses an [older version of PLONK](https://eprint.iacr.org/archive/2019/953/1584279907.pdf), and differs from it with an additional verification step done at step 8 of the PLONK verifier protocol. This requires the POC to do an additional change of the quotient polynomial evaluation opening when forging the proof compared to the steps detailed in our paper.