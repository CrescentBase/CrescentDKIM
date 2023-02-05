// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import "@openzeppelin/contracts/utils/Base64.sol";
import "@openzeppelin/contracts/utils/Strings.sol";
import "./SolRsaVerify.sol";
// import "./verifier.sol";

interface IVerifier {
  function verifyProof(uint[2] memory a, uint[2][2] memory b_verifier, uint[2] memory c, uint[1024] memory input) external returns (bool);
}

contract dkim {
    IVerifier public immutable verifier;

    constructor(IVerifier _verifier){
        verifier = _verifier;
    }

    struct PublicInputs {
        bytes32 HMUA;
        bytes32 bh;
        bytes32 base;
        bytes b;
        string canonBody;
        string newPubkey;
        uint256 nonce;
    }
    
    function verifyDkim(
        PublicInputs calldata publicInputs,
        bytes memory pubkey_n,
        bytes memory pubkey_e,
        uint[2] memory a,
        uint[2][2] memory b_verifier,
        uint[2] memory c
    ) public view {


        string memory nonceStatement = string.concat("Nonce:", Strings.toString(publicInputs.nonce));
        uint[1] memory input;


        require(
             keccak256(bytes(Base64.encode(bytes.concat(sha256(bytes(publicInputs.canonBody)))))) == keccak256(bytes.concat(publicInputs.bh))
        //   && SolRsaVerify.pkcs1Sha256Verify(base, b, pubkey_e, pubkey_n) == 0
          && contains(publicInputs.newPubkey, publicInputs.canonBody)
          && contains(nonceStatement, publicInputs.canonBody)
        //   && verifier.verifyProof(a,b_verifier,c,input) // input should be convert from HMUA+bh+base
        );
    }

    function contains (string memory word, string memory setence) public view returns(bool found) {
        bytes memory setenceBytes = bytes (setence);
        bytes memory wordBytes = bytes (word);

        require(wordBytes.length >= setenceBytes.length);

        for (uint i = 0; i <= wordBytes.length - setenceBytes.length; i++) {
            bool flag = true;
            for (uint j = 0; j < setenceBytes.length; j++)
                if (wordBytes [i + j] != setenceBytes [j]) {
                    flag = false;
                    break;
                }
            if (flag) {
                found = true;
                break;
            }
        }
        return found;
    }


    function bufferToBitArray256(bytes memory buffer) public view returns(uint8[256] memory res) {
        uint counter = 0;

        for (uint i = 0; i < buffer.length; i++) {
            for (uint j = 0; j < 8; j++) {
                res[counter] = uint8((buffer[i] >> ((7 - j) & 1)));
                counter++;
            }
        }
        return res;
    }

}


