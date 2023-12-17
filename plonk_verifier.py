import json
import sha3
import galois
from py_ecc.optimized_bn128 import FQ
from utils import GPoint, SRS, G1, G2, generator1, generator2, validate_point


def numbers_to_hash(numbers, field) -> int:
    """Hash a number."""
    engine = sha3.keccak_256()
    for number in numbers:
        if isinstance(number, tuple):
            x, y, z = number
            engine.update(bytes(hex(int(x)), "utf-8"))
            engine.update(bytes(hex(int(y)), "utf-8"))
            engine.update(bytes(hex(int(z)), "utf-8"))
        else:
            engine.update(bytes(hex(int(number)), "utf-8"))
    return field(int(engine.hexdigest(), 16) % field.order)


G1 = generator1()
G2 = generator2()


def new_call(self, at, **kwargs):
    if isinstance(at, SRS):
        coeffs = self.coeffs[::-1]
        result = at.tau1[0] * coeffs[0]
        for i in range(1, len(coeffs)):
            result += at.tau1[i] * coeffs[i]
        return result

    return galois.Poly.original_call(self, at, **kwargs)


galois.Poly.original_call = galois.Poly.__call__
galois.Poly.__call__ = new_call


def verify(proof, circuit, weak=False):
    with open(proof, "r") as f, open(circuit, "r") as g:
        proof = json.load(f)
        circuit = json.load(g)

    p = proof.pop("Fp")
    Fp = galois.GF(p)
    circuit.pop("Fp")
    for k, v in circuit.items():
        if k in ["tau", "k1", "k2", "Fp", "omega", "n"]:
            circuit[k] = Fp(v)
        elif isinstance(v, bool):
            continue
        else:
            circuit[k] = galois.Poly(coeffs=v, field=Fp)
    encrypted = circuit.pop("encrypted")
    n = int(circuit["n"])
    QM = circuit["QM"]
    QL = circuit["QL"]
    QR = circuit["QR"]
    QO = circuit["QO"]
    QC = circuit["QC"]
    S1 = circuit["S1"]
    S2 = circuit["S2"]
    S3 = circuit["S3"]
    Zh = circuit["Zh"]
    L1 = circuit["L1"]
    PI = circuit["PI"]
    tau = circuit["tau"] if not encrypted else SRS(circuit["tau"], n)
    k1 = circuit["k1"]
    k2 = circuit["k2"]
    omega = circuit["omega"]

    for k, v in proof.items():
        if isinstance(v, list):
            proof[k] = [Fp(x) for x in v]
        elif isinstance(v, str):
            proof[k] = GPoint(*[FQ(int(x)) for x in v.strip("(").strip(")").split(",")])
        else:
            proof[k] = Fp(v)

    round1 = [proof["A"], proof["B"], proof["C"]]
    round2 = [proof["Z"]]
    round3 = [proof["Tl"], proof["Tm"], proof["Th"]]
    round4 = [
        proof["a_zeta"],
        proof["b_zeta"],
        proof["c_zeta"],
        proof["s1_zeta"],
        proof["s2_zeta"],
        proof["z_omega_zeta"],
    ]
    round5 = [proof["Wzeta"], proof["Womega_zeta"]]

    # These evaluations are calculated beforehand during the setup phase
    qm_exp = QM(tau)
    ql_exp = QL(tau)
    qr_exp = QR(tau)
    qo_exp = QO(tau)
    qc_exp = QC(tau)
    s1_exp = S1(tau)
    s2_exp = S2(tau)
    s3_exp = S3(tau)

    # Values provided by the prover (round 1 to 5) is a proof.
    a_exp = round1[0]
    b_exp = round1[1]
    c_exp = round1[2]

    z_exp = round2[0]

    tl_exp = round3[0]
    tm_exp = round3[1]
    th_exp = round3[2]

    # Note: verifier has to verify that the following values are in the correct Fp field
    a_zeta, b_zeta, c_zeta, s1_zeta, s2_zeta, z_omega_zeta = round4

    w_zeta_exp = round5[0]
    w_omega_zeta_exp = round5[1]

    # Note: verifier has to verify that the following values are on the curve
    if encrypted:
        validate_point(qm_exp)
        validate_point(ql_exp)
        validate_point(qr_exp)
        validate_point(qo_exp)
        validate_point(qc_exp)
        validate_point(z_exp)
        validate_point(s1_exp)
        validate_point(s2_exp)
        validate_point(s3_exp)
        validate_point(tl_exp)
        validate_point(tm_exp)
        validate_point(th_exp)
        validate_point(a_exp)
        validate_point(b_exp)
        validate_point(c_exp)
        validate_point(w_zeta_exp)
        validate_point(w_omega_zeta_exp)

    beta = numbers_to_hash(round1 + [0], Fp)
    gamma = numbers_to_hash(round1 + [1], Fp)
    alpha = numbers_to_hash(round1 + round2, Fp)
    zeta = numbers_to_hash(round1 + round2 + round3, Fp)

    v = numbers_to_hash(round1 + round2 + round3 + round4, Fp)
    u = numbers_to_hash(round1 + round2 + round3 + round4 + round5, Fp)
    if weak:
        u = Fp(2)

    Zh_z = Zh(zeta)
    L1_z = L1(zeta)
    PI_z = PI(zeta)

    r0 = (
        PI_z
        - L1_z * alpha ** 2
        - (a_zeta + beta * s1_zeta + gamma)
        * (b_zeta + beta * s2_zeta + gamma)
        * (c_zeta + gamma)
        * z_omega_zeta
        * alpha
    )

    D_exp = (
        qm_exp * a_zeta * b_zeta
        + ql_exp * a_zeta
        + qr_exp * b_zeta
        + qo_exp * c_zeta
        + qc_exp
    )

    D_exp += z_exp * (
        (a_zeta + beta * zeta + gamma)
        * (b_zeta + beta * zeta * k1 + gamma)
        * (c_zeta + beta * zeta * k2 + gamma)
        * alpha
        + L1_z * alpha ** 2
        + u
    )

    D_exp -= (
        s3_exp
        * (a_zeta + beta * s1_zeta + gamma)
        * (b_zeta + beta * s2_zeta + gamma)
        * alpha
        * beta
        * z_omega_zeta
    )

    D_exp -= (tl_exp + tm_exp * zeta ** n + th_exp * zeta ** (2 * n)) * Zh_z

    F_exp = (
        D_exp
        + a_exp * v
        + b_exp * v ** 2
        + c_exp * v ** 3
        + s1_exp * v ** 4
        + s2_exp * v ** 5
    )

    E_exp = (
        -r0
        + v * a_zeta
        + v ** 2 * b_zeta
        + v ** 3 * c_zeta
        + v ** 4 * s1_zeta
        + v ** 5 * s2_zeta
        + u * z_omega_zeta
    )

    if encrypted:
        E_exp = G1 * E_exp

    e1 = w_zeta_exp + w_omega_zeta_exp * u
    e2 = w_zeta_exp * zeta + w_omega_zeta_exp * (u * zeta * omega) + F_exp - E_exp

    if encrypted:
        pairing1 = tau.tau2.pair(e1)
        pairing2 = G2.pair(e2)

        assert pairing1 == pairing2, "pairing1 != pairing2"
    else:

        # assert e1 * tau == e2
        return e1 * tau == e2


if __name__ == "__main__":
    print(verify("forged_proof.json", "circuit.json", True))
