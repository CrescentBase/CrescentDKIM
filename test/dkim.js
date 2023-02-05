const chai = require("chai");
const path = require("path");
const crypto = require("crypto");
const wasm_tester = require("./tester.js");
const assert = chai.assert;
const fs = require("fs");


const {bufferToBitArray, bitArrayToBuffer} = require("./helpers/utils");

function msgToBitsSHA(msg, blocks) {
    let inn = bufferToBitArray(Buffer.from(msg));
    const overall_len = blocks * 512;
    const add_bits = overall_len - inn.length;
    inn = inn.concat(Array(add_bits).fill(0));
    return inn;
}

function msgToBits(msg) {
    let inn = bufferToBitArray(Buffer.from(msg));
    return inn;
}

var cir;

async function compile() {
    console.time("Compile");
    const p = path.join(__dirname, `../circuits/dkim.circom`);
    const cir = await wasm_tester(p);
    console.timeEnd("Compile");
    return cir;
}



async function HMUAincorrect(cir) {
    const BH_LEN = 64 * 8;

    // const HMUA = (Array(SHA256_LEN).fill(1));

    // const HMUA = msgToBits("94af67700f696247cb304807e7115b26fe1587f09b855c34a3801d99ecbc8b9b"); // sha256(crescent)
    const HMUA = msgToBits(Buffer.from("14af67700f696247cb304807e7115b26fe1587f09b855c34a3801d99ecbc8b9b", 'hex')); // sha256(crescent)
    const preimageOfHMUA = "crescent";
    const fromPlusSalt = msgToBitsSHA(preimageOfHMUA,16);
    const fromPlusSaltLen = preimageOfHMUA.length * 8;

    const base = msgToBits(Buffer.from("4660378c48dfa98ed503d1135fd06df606591c9404e0f2c0592109771405a185", 'hex'));
    const preimageOfBase = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92pqoiwngriopqnwgopqiownrip4rjoqiwijre29q8hgq9wneo"; // dkim msg
    const msg = msgToBitsSHA(preimageOfBase,16); // dkim msg in bits
    const msgLen = preimageOfBase.length * 8;

    const bh = msgToBits("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");
    assert(bh.length == BH_LEN, "Illegal bhBits length");
    console.time("Generating witness");
    const witness = await cir.calculateWitness({ "HMUA": HMUA,"bh":bh, "base": base, 
                                                 "fromPlusSalt":fromPlusSalt,"msg":msg,
                                                 "fromPlusSaltLen": fromPlusSaltLen, "msgLen":msgLen }, true);                                            
    console.timeEnd("Generating witness");
}


async function correctTest(cir) {
    const BH_LEN = 64 * 8;

    // const HMUA = (Array(SHA256_LEN).fill(1));

    // const HMUA = msgToBits("94af67700f696247cb304807e7115b26fe1587f09b855c34a3801d99ecbc8b9b"); // sha256(crescent)
    const HMUA = msgToBits(Buffer.from("94af67700f696247cb304807e7115b26fe1587f09b855c34a3801d99ecbc8b9b", 'hex')); // sha256(crescent)
    const preimageOfHMUA = "crescent";
    const fromPlusSalt = msgToBitsSHA(preimageOfHMUA,16);
    const fromPlusSaltLen = preimageOfHMUA.length * 8;

    const base = msgToBits(Buffer.from("4660378c48dfa98ed503d1135fd06df606591c9404e0f2c0592109771405a185", 'hex'));
    const preimageOfBase = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92pqoiwngriopqnwgopqiownrip4rjoqiwijre29q8hgq9wneo"; // dkim msg
    const msg = msgToBitsSHA(preimageOfBase,16); // dkim msg in bits
    const msgLen = preimageOfBase.length * 8;

    const bh = msgToBits("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");
    assert(bh.length == BH_LEN, "Illegal bhBits length");
    console.log("hahahh============", HMUA+bh+base);

    const input = { "HMUA": HMUA,"bh":bh, "base": base, 
    "fromPlusSalt":fromPlusSalt,"msg":msg,
    "fromPlusSaltLen": fromPlusSaltLen, "msgLen":msgLen };

    console.time("Generating witness");
    const witness = await cir.calculateWitness(input, true);
    console.timeEnd("Generating witness");
    
    saveWitnessToLocal(input);
}

async function baseIncorrect(cir) {
    const BH_LEN = 64 * 8;

    // const HMUA = (Array(SHA256_LEN).fill(1));

    // const HMUA = msgToBits("94af67700f696247cb304807e7115b26fe1587f09b855c34a3801d99ecbc8b9b"); // sha256(crescent)
    const HMUA = msgToBits(Buffer.from("94af67700f696247cb304807e7115b26fe1587f09b855c34a3801d99ecbc8b9b", 'hex')); // sha256(crescent)
    const preimageOfHMUA = "crescent";
    const fromPlusSalt = msgToBitsSHA(preimageOfHMUA,16);
    const fromPlusSaltLen = preimageOfHMUA.length * 8;

    const base = msgToBits(Buffer.from("1660378c48dfa98ed503d1135fd06df606591c9404e0f2c0592109771405a185", 'hex'));
    const preimageOfBase = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92pqoiwngriopqnwgopqiownrip4rjoqiwijre29q8hgq9wneo"; // dkim msg
    const msg = msgToBitsSHA(preimageOfBase,16); // dkim msg in bits
    const msgLen = preimageOfBase.length * 8;

    const bh = msgToBits("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");
    assert(bh.length == BH_LEN, "Illegal bhBits length");
    console.time("Generating witness");
    const witness = await cir.calculateWitness({ "HMUA": HMUA,"bh":bh, "base": base, 
                                                 "fromPlusSalt":fromPlusSalt,"msg":msg,
                                                 "fromPlusSaltLen": fromPlusSaltLen, "msgLen":msgLen }, true);
    console.timeEnd("Generating witness");
}

async function saveWitnessToLocal(input){
    const buff= await cir.witnessCalculator.calculateWTNSBin(input,0);
	fs.writeFile(path.join("../build_circuits/" + "witness.wtns"), buff, function(err) {
	    if (err) throw err;
	});
}

async function bhIncorrect(cir) {
    const BH_LEN = 64 * 8;

    // const HMUA = (Array(SHA256_LEN).fill(1));

    // const HMUA = msgToBits("94af67700f696247cb304807e7115b26fe1587f09b855c34a3801d99ecbc8b9b"); // sha256(crescent)
    const HMUA = msgToBits(Buffer.from("94af67700f696247cb304807e7115b26fe1587f09b855c34a3801d99ecbc8b9b", 'hex')); // sha256(crescent)
    const preimageOfHMUA = "crescent";
    const fromPlusSalt = msgToBitsSHA(preimageOfHMUA,16);
    const fromPlusSaltLen = preimageOfHMUA.length * 8;

    const base = msgToBits(Buffer.from("4660378c48dfa98ed503d1135fd06df606591c9404e0f2c0592109771405a185", 'hex'));
    const preimageOfBase = "8d969eefc6c92pqoiwngriopqnwgopqiownrip4rjoqiwijre29q8hgq9wneo"; // dkim msg
    const msg = msgToBitsSHA(preimageOfBase,16); // dkim msg in bits
    const msgLen = preimageOfBase.length * 8;

    const bh = msgToBits("8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");
    assert(bh.length == BH_LEN, "Illegal bhBits length");
    console.time("Generating witness");
    const witness = await cir.calculateWitness({ "HMUA": HMUA,"bh":bh, "base": base, 
                                                 "fromPlusSalt":fromPlusSalt,"msg":msg,
                                                 "fromPlusSaltLen": fromPlusSaltLen, "msgLen":msgLen }, true);

    console.timeEnd("Generating witness");
}






describe("CRESCENT DKIM ZKP CIRCUIT", function () {
    this.timeout(1000000000);

    it ("Should compile", async () => {
        cir = await compile();
    });

    it ("Should accept", async () => {
        await correctTest(cir);
    });

    it ("Should reject bhIncorrect", async () => {
        await bhIncorrect(cir);
    });

    it ("Should reject HMUAincorrect", async () => {
        await HMUAincorrect(cir);
    });

    it ("Should reject baseIncorrect", async () => {
        await baseIncorrect(cir);
    });


    


});

