# steal_sim2.py — Steal the VFY simulator v2 (13 Nov 2026, post-match-805886cc analysis).
# Policies are REAL circuit param vectors, evaluated through the EXACT circuit
# decision list (VfyPolicyProof, solved 13 Nov):
#   (1) selfBalance < params[1]            -> FORTIFY
#   (2) oppBalance <= params[2] or p[3]==1 -> HOLD
#   (3) else                               -> EXTRACT params[0]
# Extraction amount = the ATTACKER's params[0] (circuit enforces amount == p[0], 1..10).
# Resolver mechanics are NOT published; we test the same interpretation family as
# steal_sim.py (R = fortify reduces the take by P; S = fortify shields P of balance)
# plus a sequential-resolution variant of R (A resolves first each turn).
# Fortify cost C is paid by the fortifier. Balances floor at 0. 20 turns, start 100/100.
import random

TURNS = 20

def circuit_policy(params):
    x, t_fort, t_hold, hold_flag = params[0], params[1], params[2], params[3]
    def pol(t, me, opp):
        if me < t_fort:
            return ('F', 0)
        if opp <= t_hold or hold_flag == 1:
            return ('H', 0)
        return ('E', x)
    return pol

def pol_rand(t, me, opp):
    return (random.choice('EFH'), 10)

def pol_mix(t, me, opp):
    a = random.choices('EFH', weights=[7, 1, 2])[0]
    return (a, 10)

def pol_adapt(t, me, opp):
    # adaptive archetype: fortify while behind, extract while ahead/tied
    if me < opp:
        return ('F', 0)
    return ('E', 10)

def pol_rec(t, me, opp):
    # old REC: extract unless late-game defence is profitable (handled inside play via C,P,I)
    return ('E', 10)

def take(amount, def_bal, def_act, C, P, interp):
    if amount <= 0:
        return 0
    if def_act == 'F':
        if interp in ('R', 'SEQ'):
            return max(0, min(amount, def_bal) - P)
        else:  # S
            return min(amount, max(0, def_bal - P))
    return min(amount, def_bal)

def play(pol_a, pol_b, C, P, interp, seed=0):
    random.seed(seed)
    a = b = 100
    for t in range(1, TURNS + 1):
        act_a, amt_a = pol_a(t, a, b)
        act_b, amt_b = pol_b(t, b, a)
        if interp == 'SEQ':
            # A resolves first on current balances, then B on updated balances.
            ta = take(amt_a, b, act_b, C, P, 'R') if act_a == 'E' else 0
            b = max(0, b - ta); a = a + ta
            tb = take(amt_b, a, act_a, C, P, 'R') if act_b == 'E' else 0
            a = max(0, a - tb); b = b + tb
        else:
            ta = take(amt_a, b, act_b, C, P, interp) if act_a == 'E' else 0
            tb = take(amt_b, a, act_a, C, P, interp) if act_b == 'E' else 0
            a, b = a + ta - tb, b + tb - ta
        if act_a == 'F':
            a -= C
        if act_b == 'F':
            b -= C
        a, b = max(0, a), max(0, b)
    return a, b

CANDS = {
    'CUR [10,0,0,0]':   circuit_policy([10, 0, 0, 0]),
    'F70 [10,70,0,0]':  circuit_policy([10, 70, 0, 0]),
    'F50 [10,50,0,0]':  circuit_policy([10, 50, 0, 0]),
    'F90 [10,90,0,0]':  circuit_policy([10, 90, 0, 0]),
    'E5 [5,0,0,0]':     circuit_policy([5, 0, 0, 0]),
    'E5F70 [5,70,0,0]': circuit_policy([5, 70, 0, 0]),
    'HOLD [10,0,0,1]':  circuit_policy([10, 0, 0, 1]),
}
OPPS = {
    'AE10':  circuit_policy([10, 0, 0, 0]),
    'AE5':   circuit_policy([5, 0, 0, 0]),
    'AFort': circuit_policy([10, 101, 0, 0]),
    'AHold': circuit_policy([10, 0, 0, 1]),
    'ADAPT': pol_adapt,
    'RAND':  pol_rand,
    'MIX':   pol_mix,
}
CONFIGS = []
for interp, pvals in [('R', [0, 3, 6]), ('S', [10, 30]), ('SEQ', [0, 3, 6])]:
    for P in pvals:
        for C in [2, 5]:
            CONFIGS.append((interp, C, P))

RANDOM_OPPS = {'RAND', 'MIX'}
TRIALS = 300

print(f"configs={len(CONFIGS)} opponents={len(OPPS)} turns={TURNS}")
summary = {}
detail = {}
for cname, cpol in CANDS.items():
    worst = None
    tot_diff = 0.0
    tot_pts = 0.0
    tot_n = 0
    per_opp = {}
    for oname, opol in OPPS.items():
        o_diff = 0.0; o_pts = 0.0; o_n = 0
        for (interp, C, P) in CONFIGS:
            trials = TRIALS if oname in RANDOM_OPPS else 1
            for s in range(trials):
                a, b = play(cpol, opol, C, P, interp, seed=1000 + s)
                d = a - b
                o_diff += d; o_n += 1
                o_pts += 18 if d > 0 else (9 if d == 0 else 3)
        per_opp[oname] = o_diff / o_n
        tot_diff += o_diff; tot_pts += o_pts; tot_n += o_n
        if worst is None or per_opp[oname] < worst[1]:
            worst = (oname, per_opp[oname])
    summary[cname] = (worst, tot_diff / tot_n, tot_pts / tot_n)
    detail[cname] = per_opp

print("\n=== per-opponent avg final balance diff (candidate - opponent), averaged over all configs ===")
hdr = f"{'candidate':18s}" + "".join(f"{o:>9s}" for o in OPPS)
print(hdr)
for cname in CANDS:
    print(f"{cname:18s}" + "".join(f"{detail[cname][o]:+9.1f}" for o in OPPS))
print("\n=== summary: worst-opponent avgDiff | overall avgDiff | expected match pts (18/9/3) ===")
for cname, (worst, avg, pts) in sorted(summary.items(), key=lambda kv: (kv[1][0][1], kv[1][1]), reverse=True):
    print(f"{cname:18s} worst {worst[0]:>6s} {worst[1]:+7.1f} | avg {avg:+7.1f} | pts {pts:5.2f}")
