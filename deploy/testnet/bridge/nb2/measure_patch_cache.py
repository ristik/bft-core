# measurement only: the verifier with a per-call certificate cache (an inclusion proof whose UC bytes were already judged reuses that judgment)
import sys
p = sys.argv[1]; s = open(p).read()
def rep(a, b):
    global s
    assert s.count(a) == 1, a
    s = s.replace(a, b)
rep("        uint256[4] meter; // instrumentation of test harnesses (gas metering); unused here\n    }",
    "        uint256[4] meter; // instrumentation of test harnesses (gas metering); unused here\n"
    "        bytes32[] ucKeys; // measurement: open-addressing table of UC digests already judged locally\n"
    "        bytes32[] ucState;\n        uint256[] ucTime;\n        bytes[] ucShard;\n    }")
rep("        ctx.sids = new bytes32[](_pow2(2 * steps));\n",
    "        ctx.sids = new bytes32[](_pow2(2 * steps));\n"
    "        uint256 tab = _pow2(2 * (steps + 1));\n"
    "        ctx.ucKeys = new bytes32[](tab);\n        ctx.ucState = new bytes32[](tab);\n        ctx.ucTime = new uint256[](tab);\n        ctx.ucShard = new bytes[](tab);\n")
old = s[s.index("        Cfg memory c = ctx.cfg;\n        (\n            bytes4 rule,"):s.index("        _require(ctx, _inShard(shard, sid), R.INCLUSION_PROOF);")]
new = """        (bytes32 stateHash, uint256 timestamp, bytes memory shard) = _certCached(ctx, s.ucPos, s.ucLen);
"""
s = s.replace(old, new)
rep("    function _inShard(bytes memory shard, bytes32 sid) internal pure returns (bool) {",
"""    /// @dev measurement: certificate() once per distinct UC byte string of the call; a repeated UC reuses the judgment (its claim is
    ///      already pending, identical claims are flushed once anyway).
    function _certCached(Ctx memory ctx, uint256 up, uint256 ul)
        internal
        view
        returns (bytes32 stateHash, uint256 timestamp, bytes memory shard)
    {
        bytes32 h;
        assembly ("memory-safe") {
            let m := mload(0x40)
            calldatacopy(m, up, ul)
            h := keccak256(m, ul)
        }
        if (h == 0) h = bytes32(uint256(1));
        uint256 mask = ctx.ucKeys.length - 1;
        uint256 i = uint256(h) & mask;
        while (ctx.ucKeys[i] != 0 && ctx.ucKeys[i] != h) i = (i + 1) & mask;
        if (ctx.ucKeys[i] == h) return (ctx.ucState[i], ctx.ucTime[i], ctx.ucShard[i]);
        Cfg memory c = ctx.cfg;
        bytes4 rule;
        bytes memory claim;
        (rule, claim, stateHash, timestamp, shard) = RECEIPTS.certificate(_cdSlice(up, ul), c.network, c.aggPartition);
        if (rule != 0) _fail(ctx, rule);
        ctx.claims[ctx.nClaims++] = Claim(claim, false);
        ctx.ucKeys[i] = h;
        ctx.ucState[i] = stateHash;
        ctx.ucTime[i] = timestamp;
        ctx.ucShard[i] = shard;
    }

    function _inShard(bytes memory shard, bytes32 sid) internal pure returns (bool) {""")
open(p, 'w').write(s)
