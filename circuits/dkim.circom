pragma circom 2.0.3;

include "./sha256Bytes.circom";
include "./contains.circom";
include "./concat.circom";
include "./sha256Pad.circom";


template dkim(BlockSpace) {

    // constant
    var BLOCK_LEN = 1024;
    var SHA256_LEN = 32;
    var BH_LEN = 64;
    
    // public statments
    signal input HMUA[SHA256_LEN]; // Hidden Mail User Agent = sha256(fromPlusSalt)
    signal input bh[BH_LEN]; // bh, bodyhash = sha256(Canon-body)
    signal input base[SHA256_LEN]; //base == sha256(msg)


    // secret witnesses
    signal input from[BLOCK_LEN];
    signal input salt[BLOCK_LEN];
    signal input msg[BLOCK_LEN];
    signal input fromLen;
    signal input saltLen;
    signal input msgLen;

    // from + salt
    component concatArr = Concat(BLOCK_LEN);
    concatArr.in1_len <== fromLen;
    for (var i = 0; i < BLOCK_LEN; i++) {
        concatArr.in1[i] <== from[i];
        concatArr.in2[i] <== salt[i];
    }

    // HMUA == she(from + salt)
    component pad = Sha256Pad(BLOCK_LEN);
    pad.in_len <== fromLen + saltLen;
    for (var i = 0; i < BLOCK_LEN; i++) {
        pad.in[i] <== concatArr.out[i];
    }

    component hmuaHasher = Sha256Bytes(BLOCK_LEN);
    hmuaHasher.in_len_padded_bytes <== pad.prepadLen;
    for (var i = 0; i < BLOCK_LEN; i++) {
        hmuaHasher.in_padded[i] <== pad.prepadOut[i];
    }

    component hmuaB2n[SHA256_LEN];
    for (var i = 0; i < SHA256_LEN; i++) {
        hmuaB2n[i] = Bits2Num(BlockSpace);
        for (var j = BlockSpace - 1; j >= 0; j--) {
            hmuaB2n[i].in[BlockSpace - 1 - j] <== hmuaHasher.out[i * BlockSpace + j];
        }
        HMUA[i] === hmuaB2n[i].out;
    }

    // base == she(msg)
    component msgPad = Sha256Pad(BLOCK_LEN);
    msgPad.in_len <== msgLen;
    for (var i = 0; i < BLOCK_LEN; i++) {
        msgPad.in[i] <== msg[i];
    }

    component msgHasher = Sha256Bytes(BLOCK_LEN);
    msgHasher.in_len_padded_bytes <== msgPad.prepadLen;
    for (var i = 0; i < BLOCK_LEN; i++) {
        msgHasher.in_padded[i] <== msgPad.prepadOut[i];
    }

    component msgB2n[SHA256_LEN];
    for (var i = 0; i < SHA256_LEN; i++) {
        msgB2n[i] = Bits2Num(BlockSpace);
        for (var j = BlockSpace - 1; j >= 0; j--) {
            msgB2n[i].in[BlockSpace - 1 - j] <== msgHasher.out[i * BlockSpace + j];
        }
        base[i] === msgB2n[i].out;
    }

    // bh ∈ msg checker
    component msgContainsBh = contains(BLOCK_LEN);
    msgContainsBh.in1_len <== msgLen;
    msgContainsBh.in2_len <== SHA256_LEN;
    for (var i = 0; i < BLOCK_LEN; i++) {
        msgContainsBh.in1[i] <== msg[i];
        if (i < SHA256_LEN) {
            msgContainsBh.in2[i] <== bh[i];
        } else {
            msgContainsBh.in2[i] <== 0;
        }
    }

    // from ∈ msg checker
    component contains = contains(BLOCK_LEN);
    contains.in1_len <== msgLen;
    contains.in2_len <== fromLen;
    for (var i = 0; i < BLOCK_LEN; i++) {
        contains.in1[i] <== msg[i];
        contains.in2[i] <== from[i];
    }
}

component main  {public [HMUA]}= dkim(8);




