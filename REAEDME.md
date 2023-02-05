
# Crescent DKIM


# 
1. `npm install`
2. `npm install -g mocha`
3. 


# Generate solidity call
1. Generate witness
`mocha dkim.js`

2. Create proof
`snarkjs groth16 prove dkim_final.zkey witness.wtns proof.json public.json`

3. Solidity call

