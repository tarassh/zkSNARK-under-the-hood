// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

contract MalleableProof {
    Groth16Verifier public verifier;

    uint256 constant q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    uint256[2] pA = [
        0x043dda925746db6abbc4a47f307c89fc64095025b0404f231e5a25b7d99f142f,
        0x27cd7c96181a03be504ec161b1fc3f68678ed1c4b7ea2e6347447d7df01f198c
    ];
    uint256[2][2] pB = [
        [
            0x010cd93d727ed43d29b02d8abb33b6c535ce4e9d76abeba8a017edab2c578697,
            0x08fb3dd1336516c8eb3451cc40047ae22ea75a8a39e5a25353b058f815f4ee27
        ],
        [
            0x0927c4e2813c2446764cd5ccbe0e9a71d05d8dfcb1b88024ab987882815e8e3a,
            0x188dee86bd4ff36704ff3d8ce1ce5cc79c024feb3d212d9a6d0026bf7e9c6394
        ]
    ];
    uint256[2] pC = [
        0x23f2b9fbb1af6b96e377e8ed3083f0815a6b013461bceee665bde037e22b87b8,
        0x1bcf05d9624319e7373ed846cfff7f5f7e6b8d2cc8b4860c8e11c3e91c1019ad
    ];
    uint256[1] pubSignals = [
        uint256(
            0x000000000000000000000000000000000000000000000000000000000000005c
        )
    ];

    constructor() {
        verifier = new Groth16Verifier();
    }

    function negate(uint256[2] memory point) internal pure returns (uint256[2] memory) {
        return [point[0], uint256(q - (point[1] % q))];
    }

    function negate(uint256[2][2] memory points) internal pure returns (uint256[2][2] memory) {
        return [[points[0][0], points[0][1]], [uint256(q - points[1][0] % q), uint256(q - (points[1][1] % q))]];
    }

    function test() public view returns(bool) {
        uint256[2] memory pA_neg = negate(pA);
        uint256[2][2] memory pB_neg = negate(pB);

        bytes32 originalProofHash = keccak256(abi.encodePacked(pA[0], pA[1], pB[0][0], pB[0][1], pB[1][0], pB[1][1], pC[0], pC[1], pubSignals[0]));
        bytes32 malleableProofHash = keccak256(abi.encodePacked(pA_neg[0], pA_neg[1], pB_neg[0][0], pB_neg[0][1], pB_neg[1][0], pB_neg[1][1], pC[0], pC[1], pubSignals[0]));

        require(originalProofHash != malleableProofHash, "proofs are equal");

        require(verifier.verifyProof(pA, pB, pC, pubSignals), "original proof failed");
        require(verifier.verifyProof(pA_neg, pB_neg, pC, pubSignals), "malleable proof failed");

        return true;
    }
}

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax =
        11902296347347039061914403575092544846359038134537957629176655874298370699911;
    uint256 constant alphay =
        3391855710907380668233433519135265813497031220290585864635015352649111711184;
    uint256 constant betax1 =
        16784052509360644757629301015206259316198090538012176085893013905461802331831;
    uint256 constant betax2 =
        12553085197744738873343062641154648040227321273919470712379455912841029058108;
    uint256 constant betay1 =
        19432553154467640750076643403468969701277919142567543087647109772606325611215;
    uint256 constant betay2 =
        10009875844390438955602042708425754795331778042892155353502209313012220600786;
    uint256 constant gammax1 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 =
        1899311077018330499661076917249789522364858944299631094464619341448064208677;
    uint256 constant deltax2 =
        2940006217620028071483555626688027143173059468880178649085394490329969301309;
    uint256 constant deltay1 =
        9341687543023852914223671728476937889999092849725638929381204194633096037884;
    uint256 constant deltay2 =
        17862496793411495277768192323260065881295964168547115804420567672808037688434;

    uint256 constant IC0x =
        17400396001955266182761672048518979776362947284593388197557812120968484015363;
    uint256 constant IC0y =
        7077915839858152427525208697187383436168898719005308255598939504725845408697;

    uint256 constant IC1x =
        14504255466195739587178955895060518312474127917266890870496962379534421099402;
    uint256 constant IC1y =
        17537483151726991648505521566767322181363618458103336910347616663390669720764;

    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[1] calldata _pubSignals
    ) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, q)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x

                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(
                    add(_pPairing, 32),
                    mod(sub(q, calldataload(add(pA, 32))), q)
                )

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))

                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)

                let success := staticcall(
                    sub(gas(), 2000),
                    8,
                    _pPairing,
                    768,
                    _pPairing,
                    0x20
                )

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F

            checkField(calldataload(add(_pubSignals, 0)))

            checkField(calldataload(add(_pubSignals, 32)))

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
            return(0, 0x20)
        }
    }
}
