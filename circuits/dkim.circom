pragma circom 2.0.3;

include "./Sha256Var.circom";
include "./contains.circom";


template dkim(BlockSpace) {

    // constant
    var BLOCK_LEN = 512;
    var SHA256_LEN = 256;
    var BH_LEN = 64 * 8;

    // variable
    var maxBlockCount = pow(2, BlockSpace);
    var maxLen = BLOCK_LEN * maxBlockCount;
    
    // public statments
    signal input HMUA[SHA256_LEN]; // Hidden Mail User Agent = sha256(fromPlusSalt)
    signal input bh[BH_LEN]; // bh, bodyhash = sha256(Canon-body)
    signal input base[SHA256_LEN]; //base == sha256(msg)


    // secret witnesses
    signal input fromPlusSalt[maxLen];
    signal input msg[maxLen];
    signal input fromPlusSaltLen;
    signal input msgLen;

    
    // HMUA Checker
    component hmuaHasher = Sha256Var(BlockSpace);
    hmuaHasher.len <== fromPlusSaltLen;
    for (var i = 0; i < maxLen; i++) {
        hmuaHasher.in[i] <== fromPlusSalt[i];
    }    

    for (var i = 0; i < SHA256_LEN; i++) {
        HMUA[i] === hmuaHasher.out[i];
    }

    // base checker
    component baseHasher = Sha256Var(BlockSpace);
    baseHasher.len <== msgLen;
    for (var i = 0; i < maxLen; i++) {
        baseHasher.in[i] <== msg[i];
    }    

    for (var i = 0; i < SHA256_LEN; i++) {
        base[i] === baseHasher.out[i];
    }


    // bh ∈ msg checker
    component contains = contains(maxLen, BH_LEN); 
    for (var i = 0; i < BH_LEN; i++) {
        contains.bh[i] <== bh[i];
    }

    for (var i = 0; i < maxLen; i++) {
        contains.msg[i] <== msg[i];
    }    
}

component main  {public [HMUA, bh, base]}= dkim(4);




