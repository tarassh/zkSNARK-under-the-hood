// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

contract PairingTest {

    // A
    uint256 constant aG1_x =
        19092006581455788758709004813424108450475230671546198110182704126760952021248;
    uint256 constant aG1_y =
        18428185916649502171614192229986655674799279684527591370328182794110727996633;

    // A + alpha
    uint256 constant aAlphaG1_x =
        21217661085126559093618422090976331652552329149903126494066087883598376875544;
    uint256 constant aAlphaG1_y =
        1457628392657713667261954926657021903011012448011727187218226314692374545095;

    // B
    uint256 constant bG2_x1 =
        1110332524507442648511549408896049077062269578877062826069065960274388112308;
    uint256 constant bG2_x2 =
        15815785354885964222010325771656100864105333417560377595802485750386873282739;
    uint256 constant bG2_y1 =
        20784382045877636010618629654573620888044404319093695781168988411617616204166;
    uint256 constant bG2_y2 =
        5234804291052944426941184034424257962428641145809086397589880058685491457835;

    // B + beta
    uint256 constant bBetaG2_x1 =
        20161228061684815865099911872839200995540444693651642652647237181803620563806;
    uint256 constant bBetaG2_x2 =
        3702101514282117915522831058779841268903928207744078940223053989381497029466;
    uint256 constant bBetaG2_y1 =
        10171191431308550184748354830658581789465772250477170345556065080802755639143;
    uint256 constant bBetaG2_y2 =
        8100553438456289002589059492494523752698638511437509279692551834728598369443;

    // alpha
    uint256 constant alphaG1_x =
        12852522211178622728088728121177131998585782282560100422041774753646305409836;
    uint256 constant alphaG1_y =
        15918672909255108529698304535345707578139606904951176064731093256171019744261;

    // beta
    uint256 constant betaG2_x1 =
        13336051216799233397425171705413019817432261264277553698851043903438362044019;
    uint256 constant betaG2_x2 =
        4223541897218034772489308554703631900412225505600032161509417263929627799922;
    uint256 constant betaG2_y1 =
        8589690792863225986668482066667610564954409227406711133301860665960659900589;
    uint256 constant betaG2_y2 =
        3464479980965492933832392178094394811175104694227548891696772752598149662990;

    uint256 constant cG1_x =
        21755526246297599392782387322262927251662305599666002632514868138515690603377;
    uint256 constant cG1_y =
        19883332083442129478217826420060112230198011363938980948134718366700920887106;

    uint256 constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    uint256 constant G2_x1 = 
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant G2_x2 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant G2_y1 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant G2_y2 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        if (p.x == 0 && p.y == 0) return G1Point(0, 0);
        return G1Point(p.x, Q - (p.y % Q));
    }

    function add(
        G1Point memory p1,
        G1Point memory p2
    ) public view returns (G1Point memory r) {
        (bool ok, bytes memory result) = address(6).staticcall(
            abi.encode(p1.x, p1.y, p2.x, p2.y)
        );
        require(ok, "g1add failed");
        (uint256 x, uint256 y) = abi.decode(result, (uint256, uint256));
        r = G1Point(x, y);
    }

    function run(bytes memory input) public view returns (bool) {
        // optional, the precompile checks this too and reverts (with no error) if false, this helps narrow down possible errors
        if (input.length % 192 != 0) revert("Points must be a multiple of 6");
        (bool success, bytes memory data) = address(0x08).staticcall(input);
        if (success) return abi.decode(data, (bool));
        revert("Wrong pairing");
    }

    function verify() public view returns (bool) {
        // -(A + aplha) * (B + beta) + alpha * beta + C + beta * A + aplha * B = 0
        bytes memory points1 = abi.encode(
            aAlphaG1_x,
            negate(G1Point(aAlphaG1_x, aAlphaG1_y)).y,
            bBetaG2_x2,
            bBetaG2_x1,
            bBetaG2_y2,
            bBetaG2_y1,
            alphaG1_x,
            alphaG1_y,
            betaG2_x2,
            betaG2_x1,
            betaG2_y2,
            betaG2_y1
        );

        bytes memory points2 = abi.encode(
            cG1_x,
            cG1_y,
            G2_x2,
            G2_x1,
            G2_y2,
            G2_y1,
            aG1_x,
            aG1_y,
            betaG2_x2,
            betaG2_x1,
            betaG2_y2,
            betaG2_y1
        );

        bytes memory points3 = abi.encode(
            alphaG1_x,
            alphaG1_y,
            bG2_x2,
            bG2_x1,
            bG2_y2,
            bG2_y1
        );

        bytes memory points = abi.encodePacked(points1, points2, points3);

        bool x = run(points);
        return x;
    }
}
