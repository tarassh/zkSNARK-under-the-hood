from galois import Poly, GF
import numpy as np
from py_ecc.optimized_bn128 import (
    multiply,
    G1,
    G2,
    add,
    normalize,
    curve_order,
)
from string import Template

# p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
p = curve_order
FP = GF(p)


class QAP:
    def __init__(self, L: Poly, R: Poly, O: Poly, T: Poly):
        self.L = L
        self.R = R
        self.O = O
        self.T = T

    def __repr__(self):
        s = f"""
        ----- QAP -----
        L = {self.L}
        R = {self.R}
        O = {self.O}
        T = {self.T}
        """
        return s


class ProverKey:
    def __init__(
        self,
        tau_G1,
        tau_G2,
        alpha_G1,
        beta_G1,
        beta_G2,
        delta_G1,
        delta_G2,
        K_delta_G1,
        target_G1,
    ):
        self.tau_G1 = tau_G1
        self.tau_G2 = tau_G2
        self.alpha_G1 = alpha_G1
        self.beta_G1 = beta_G1
        self.beta_G2 = beta_G2
        self.delta_G1 = delta_G1
        self.delta_G2 = delta_G2
        self.K_delta_G1 = K_delta_G1
        self.target_G1 = target_G1

    def __repr__(self):
        s = f"""
----- Prover Key -----
[τ]G1 = {[normalize(point) for point in self.tau_G1]}
[τ]G2 = {[normalize(point) for point in self.tau_G2]}
[α]G1 = {normalize(self.alpha_G1)}
[β]G1 = {normalize(self.beta_G1)}
[β]G2 = {normalize(self.beta_G2)}
[δ]G1 = {normalize(self.delta_G1)}
[δ]G2 = {normalize(self.delta_G2)}
[K/δ]G1 = {[normalize(point) for point in self.K_delta_G1]}
[τT(τ)/δ]G1 = {[normalize(point) for point in self.target_G1]}
        """
        return s


class VerifierKey:
    def __init__(self, alpha_G1, beta_G2, gamma_G2, delta_G2, K_gamma_G1):
        self.alpha_G1 = alpha_G1
        self.beta_G2 = beta_G2
        self.gamma_G2 = gamma_G2
        self.delta_G2 = delta_G2
        self.K_gamma_G1 = K_gamma_G1

    def __repr__(self):
        n_vk = self.normalize()
        s = f"""
----- Verifier Key -----
[α]G1 = {n_vk.alpha_G1}
[β]G2 = {n_vk.beta_G2}
[γ]G2 = {n_vk.gamma_G2}
[δ]G2 = {n_vk.delta_G2}
[K/γ]G1 = {n_vk.K_gamma_G1}
        """
        return s

    def normalize(self):
        return VerifierKey(
            normalize(self.alpha_G1),
            normalize(self.beta_G2),
            normalize(self.gamma_G2),
            normalize(self.delta_G2),
            [normalize(point) for point in self.K_gamma_G1],
        )


class Proof:
    def __init__(self, A, B, C):
        self.A = A
        self.B = B
        self.C = C

    def __repr__(self):
        n_proof = self.normalize()
        s = f"""
----- Proof -----
A = {n_proof.A}
B = {n_proof.B}
C = {n_proof.C}
        """
        return s

    def normalize(self):
        return Proof(normalize(self.A), normalize(self.B), normalize(self.C))


def keygen(qap: QAP):  # -> (ProverKey, VerifierKey)
    # generating toxic waste
    alpha = FP(2)
    beta = FP(3)
    gamma = FP(4)
    delta = FP(5)
    tau = FP(20)

    beta_L = beta * qap.L
    alpha_R = alpha * qap.R
    K = beta_L + alpha_R + qap.O
    Kp = to_poly(K)
    K_eval = evaluate_poly_list(Kp, tau)

    T_tau = qap.T(tau)

    pow_tauTtau_div_delta = [
        (tau ** i * T_tau) / delta for i in range(0, qap.T.degree - 1)
    ]
    target_G1 = [multiply(G1, int(pTd)) for pTd in pow_tauTtau_div_delta]

    K_gamma, K_delta = [k / gamma for k in K_eval[:2]], [k / delta for k in K_eval[2:]]

    # generating SRS
    tau_G1 = [multiply(G1, int(tau ** i)) for i in range(0, qap.T.degree)]
    tau_G2 = [multiply(G2, int(tau ** i)) for i in range(0, qap.T.degree)]
    alpha_G1 = multiply(G1, int(alpha))
    beta_G1 = multiply(G1, int(beta))
    beta_G2 = multiply(G2, int(beta))
    gamma_G2 = multiply(G2, int(gamma))
    delta_G1 = multiply(G1, int(delta))
    delta_G2 = multiply(G2, int(delta))
    K_gamma_G1 = [multiply(G1, int(k)) for k in K_gamma]
    K_delta_G1 = [multiply(G1, int(k)) for k in K_delta]

    pk = ProverKey(
        tau_G1,
        tau_G2,
        alpha_G1,
        beta_G1,
        beta_G2,
        delta_G1,
        delta_G2,
        K_delta_G1,
        target_G1,
    )

    vk = VerifierKey(alpha_G1, beta_G2, gamma_G2, delta_G2, K_gamma_G1)

    return pk, vk


def prove(pk: ProverKey, w_pub: [], w_priv: [], qap: QAP):
    r = FP(12)
    s = FP(13)

    w = FP(np.concatenate((w_pub, w_priv)))

    U = Poly((w @ qap.L)[::-1])
    V = Poly((w @ qap.R)[::-1])
    W = Poly((w @ qap.O)[::-1])

    H = (U * V - W) // qap.T
    rem = (U * V - W) % qap.T

    assert rem == 0

    # [K/δ*w]G1
    Kw_delta_G1_terms = [
        multiply(point, int(scaler)) for point, scaler in zip(pk.K_delta_G1, w_priv)
    ]
    Kw_delta_G1 = Kw_delta_G1_terms[0]
    for i in range(1, len(Kw_delta_G1_terms)):
        Kw_delta_G1 = add(Kw_delta_G1, Kw_delta_G1_terms[i])

    r_delta_G1 = multiply(pk.delta_G1, int(r))
    s_delta_G1 = multiply(pk.delta_G1, int(s))
    s_delta_G2 = multiply(pk.delta_G2, int(s))

    A_G1 = evaluate_poly(U, pk.tau_G1)
    A_G1 = add(A_G1, pk.alpha_G1)
    A_G1 = add(A_G1, r_delta_G1)

    B_G2 = evaluate_poly(V, pk.tau_G2)
    B_G2 = add(B_G2, pk.beta_G2)
    B_G2 = add(B_G2, s_delta_G2)

    B_G1 = evaluate_poly(V, pk.tau_G1)
    B_G1 = add(B_G1, pk.beta_G1)
    B_G1 = add(B_G1, s_delta_G1)

    As_G1 = multiply(A_G1, int(s))
    Br_G1 = multiply(B_G1, int(r))
    rs_delta_G1 = multiply(pk.delta_G1, int(-r * s))

    HT_G1 = evaluate_poly(H, pk.target_G1)

    C_G1 = add(Kw_delta_G1, HT_G1)
    C_G1 = add(C_G1, As_G1)
    C_G1 = add(C_G1, Br_G1)
    C_G1 = add(C_G1, rs_delta_G1)

    return Proof(A_G1, B_G2, C_G1)


def create_verifier(
    vk: VerifierKey, w_pub: [], proof: Proof, filename="PairingCheck.sol"
):
    proof = proof.normalize()
    vk = vk.normalize()
    with open("VerifierPublicInputGammaDelta.sol.template", "r") as f:
        template = Template(f.read())
        variables = {
            "aG1_x": proof.A[0],
            "aG1_y": proof.A[1],
            "bG2_x1": proof.B[0].coeffs[0],
            "bG2_x2": proof.B[0].coeffs[1],
            "bG2_y1": proof.B[1].coeffs[0],
            "bG2_y2": proof.B[1].coeffs[1],
            "cG1_x": proof.C[0],
            "cG1_y": proof.C[1],
            "alphaG1_x": vk.alpha_G1[0],
            "alphaG1_y": vk.alpha_G1[1],
            "betaG2_x1": vk.beta_G2[0].coeffs[0],
            "betaG2_x2": vk.beta_G2[0].coeffs[1],
            "betaG2_y1": vk.beta_G2[1].coeffs[0],
            "betaG2_y2": vk.beta_G2[1].coeffs[1],
            "k1G1_x": vk.K_gamma_G1[0][0],
            "k1G1_y": vk.K_gamma_G1[0][1],
            "k2G1_x": vk.K_gamma_G1[1][0],
            "k2G1_y": vk.K_gamma_G1[1][1],
            "gammaG2_x1": vk.gamma_G2[0].coeffs[0],
            "gammaG2_x2": vk.gamma_G2[0].coeffs[1],
            "gammaG2_y1": vk.gamma_G2[1].coeffs[0],
            "gammaG2_y2": vk.gamma_G2[1].coeffs[1],
            "deltaG2_x1": vk.delta_G2[0].coeffs[0],
            "deltaG2_x2": vk.delta_G2[0].coeffs[1],
            "deltaG2_y1": vk.delta_G2[1].coeffs[0],
            "deltaG2_y2": vk.delta_G2[1].coeffs[1],
            "one": w_pub[0],
            "out": w_pub[1],
        }
        output = template.substitute(variables)

    with open(filename, "w") as f:
        f.write(output)


def to_poly(mtx):
    poly_list = []
    for i in range(0, mtx.shape[0]):
        poly_list.append(Poly(mtx[i][::-1]))
    return poly_list


def evaluate_poly_list(poly_list, x):
    results = []
    for poly in poly_list:
        results.append(poly(x))
    return results


def evaluate_poly(poly, trusted_points, verbose=False):
    coeff = poly.coefficients()[::-1]

    assert len(coeff) == len(trusted_points), "Polynomial degree mismatch!"

    if verbose:
        [print(normalize(point)) for point in trusted_points]

    terms = [multiply(point, int(coeff)) for point, coeff in zip(trusted_points, coeff)]
    evaluation = terms[0]
    for i in range(1, len(terms)):
        evaluation = add(evaluation, terms[i])

    if verbose:
        print("-" * 10)
        print(normalize(evaluation))
    return evaluation
