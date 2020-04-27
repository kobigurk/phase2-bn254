template Num2Bits(n) {
    signal input in;
    signal intermediate[n];
    signal output out[n];
    var lc1=0;

    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        intermediate[i] <== out[i] * out[i];
        lc1 += out[i] * 2**i;
    }

    lc1 === in;
}

component main = Num2Bits(253);
