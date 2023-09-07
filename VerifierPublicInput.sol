// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

contract PairingTest {

    // A
    uint256 constant aG1_x =
        1386024683863798223806715768494499062004541323940181712423964207525793364711;
    uint256 constant aG1_y =
        140843658074195725477996606607942635995385653032596678292076222071924134;

    // B
    uint256 constant bG2_x1 =
        2268131489099612700799057509317325492629365410973939712610009952960246451283;
    uint256 constant bG2_x2 =
        5460202898618824449851004635208915161845252587893842541197344609059159079041;
    uint256 constant bG2_y1 =
        21214978237453897862935673366579439999311734514850735211426933843714547507738;
    uint256 constant bG2_y2 =
        20956792494964230503385709419527449681227575755609196682056154158621712303733;

    // alpha
    uint256 constant alphaG1_x =
        1368015179489954701390400359078579693043519447331113978918064868415326638035;
    uint256 constant alphaG1_y =
        9918110051302171585080402603319702774565515993150576347155970296011118125764;

    // beta
    uint256 constant betaG2_x1 =
        2725019753478801796453339367788033689375851816420509565303521482350756874229;
    uint256 constant betaG2_x2 =
        7273165102799931111715871471550377909735733521218303035754523677688038059653;
    uint256 constant betaG2_y1 =
        2512659008974376214222774206987427162027254181373325676825515531566330959255;
    uint256 constant betaG2_y2 =
        957874124722006818841961785324909313781880061366718538693995380805373202866;

    // C
    uint256 constant cG1_x =
        3007959184562619447308758040351540166633693812660366965459472595743782653474;
    uint256 constant cG1_y =
        21613286137401577200129067304160980059729655631955179340440670659782625352184;

    // K 
    uint256 constant kG1_x =
        2285801182806610770657419494535950855770340693072843615122889807967969315919;
    uint256 constant kG1_y =
        18123511326312116315687556134605188595130818916602058636606420458000478513163;

    uint256 constant G2_x1 =
        10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant G2_x2 =
        11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant G2_y1 =
        8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant G2_y2 =
        4082367875863433681332203403145435568316851327593401208105741076214120093531;

    uint256 constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        if (p.x == 0 && p.y == 0) return G1Point(0, 0);
        return G1Point(p.x, Q - (p.y % Q));
    }

    function run(bytes memory input) public view returns (bool) {
        // optional, the precompile checks this too and reverts (with no error) if false, this helps narrow down possible errors
        if (input.length % 192 != 0) revert("Points must be a multiple of 6");
        (bool success, bytes memory data) = address(0x08).staticcall(input);
        if (success) return abi.decode(data, (bool));
        revert("Wrong pairing");
    }

    function verify() public view returns (bool) {
        // -A * B + alpha * beta + C = 0
        bytes memory points1 = abi.encode(
            aG1_x,
            negate(G1Point(aG1_x, aG1_y)).y,
            bG2_x2,
            bG2_x1,
            bG2_y2,
            bG2_y1,
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
            kG1_x,
            kG1_y,
            G2_x2,
            G2_x1,
            G2_y2,
            G2_y1
        );

        bytes memory points = abi.encodePacked(points1, points2);

        bool x = run(points);
        return x;
    }
}
