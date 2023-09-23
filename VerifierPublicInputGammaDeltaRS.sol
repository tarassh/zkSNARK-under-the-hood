// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.9;

contract PairingTest {

    uint256 constant Q =
        21888242871839275222246405745257275088696311157297823662689037894645226208583;

    struct G1Point {
        uint256 x;
        uint256 y;
    }

    struct G2Point {
        uint256 x1;
        uint256 x2;
        uint256 y1;
        uint256 y2;
    }

    struct Proof {
        G1Point A;
        G2Point B;
        G1Point C;
    }

    struct VerifierKey {
        G1Point alpha;
        G2Point beta;
        G2Point gamma;
        G2Point delta;
        G1Point IC0;
        G1Point IC1;
    }

    // proof has to be supplied by the user, but for demo purposes we just hardcode it
    function proof() public pure returns (Proof memory p) {
        p = Proof(
            G1Point(14614942786781395235323739941473784359708158727987721451462286880826505164913, 21619883166399935899647001848432357053098942563907854290524692662449417028110),
            G2Point(319587749637165176148886793271196602371225601986791290743038843027662975010, 3799125525057959973194726334738911206921416163026998466480194981504341041059, 14804322218212369892528022736659815952157535301541362469519071425927767448738, 15320077395654528648820749046262517324306647091379407731658843025099270151841),
            G1Point(17701753435269740403921105970374551089935320911024962898677727136701795584514, 14346862312910190547529197118974415823038018600073367279111060787975692996852)
        );
    }

    function input() public pure returns (uint256[2] memory _input) {
        _input[0] = 1;
        _input[1] = 104;
    }

    function verifierKey() public pure returns (VerifierKey memory vk) {
        vk = VerifierKey(
            G1Point(1368015179489954701390400359078579693043519447331113978918064868415326638035, 9918110051302171585080402603319702774565515993150576347155970296011118125764),
            G2Point(2725019753478801796453339367788033689375851816420509565303521482350756874229, 7273165102799931111715871471550377909735733521218303035754523677688038059653, 2512659008974376214222774206987427162027254181373325676825515531566330959255, 957874124722006818841961785324909313781880061366718538693995380805373202866),
            G2Point(18936818173480011669507163011118288089468827259971823710084038754632518263340, 18556147586753789634670778212244811446448229326945855846642767021074501673839, 18825831177813899069786213865729385895767511805925522466244528695074736584695, 13775476761357503446238925910346030822904460488609979964814810757616608848118),
            G2Point(20954117799226682825035885491234530437475518021362091509513177301640194298072, 4540444681147253467785307942530223364530218361853237193970751657229138047649, 21508930868448350162258892668132814424284302804699005394342512102884055673846, 11631839690097995216017572651900167465857396346217730511548857041925508482915),
            G1Point(0, 0),
            G1Point(1540147615742092855122362390273215696202300989980535937807544369063691019287, 916302540883947080468652904864832717784863855769927076757632797189693955321)
        );
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

    function mul(
        G1Point memory p,
        uint256 scalar
    ) public view returns (G1Point memory r) {
        (bool ok, bytes memory result) = address(7).staticcall(
            abi.encode(p.x, p.y, scalar)
        );
        require(ok, "g1mul failed");
        (uint256 x, uint256 y) = abi.decode(result, (uint256, uint256));
        r = G1Point(x, y);
    }

    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        if (p.x == 0 && p.y == 0) return G1Point(0, 0);
        return G1Point(p.x, Q - (p.y % Q));
    }

    function run(bytes memory _input) public view returns (bool) {
        // optional, the precompile checks this too and reverts (with no error) if false, this helps narrow down possible errors
        if (_input.length % 192 != 0) revert("Points must be a multiple of 6");
        (bool success, bytes memory data) = address(0x08).staticcall(_input);
        if (success) return abi.decode(data, (bool));
        revert("Wrong pairing");
    }

    function emulate() public view returns(bool) {
        return verify(proof().A, proof().B, proof().C, input());
    }

    function verify(G1Point memory A, G2Point memory B, G1Point memory C, uint256[2] memory _input) public view returns (bool) {
        G1Point memory k1 = mul(verifierKey().IC0, _input[0]);
        G1Point memory k2 = mul(verifierKey().IC1, _input[1]);
        G1Point memory K = add(k1, k2);

        // -A * B + alpha * beta + C * delta + K * gamma = 0
        bytes memory points1 = abi.encode(
            A.x,
            negate(A).y,
            B.x2,
            B.x1,
            B.y2,
            B.y1,
            verifierKey().alpha.x,
            verifierKey().alpha.y,
            verifierKey().beta.x2,
            verifierKey().beta.x1,
            verifierKey().beta.y2,
            verifierKey().beta.y1
        );

        bytes memory points2 = abi.encode(
            C.x,
            C.y,
            verifierKey().delta.x2,
            verifierKey().delta.x1,
            verifierKey().delta.y2,
            verifierKey().delta.y1,
            K.x,
            K.y,
            verifierKey().gamma.x2,
            verifierKey().gamma.x1,
            verifierKey().gamma.y2,
            verifierKey().gamma.y1
        );

        bytes memory points = abi.encodePacked(points1, points2);
        return run(points);
    }
}
