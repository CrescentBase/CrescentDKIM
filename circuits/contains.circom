pragma circom 2.0.3;


template contains(maxLen) {
    signal input in1[maxLen];
    signal input in2[maxLen];

    signal input in1_len;
    signal input in2_len;
    
    var counter_max = 0;
    for (var i = 0; i < maxLen; i++) {
        if (i < in1_len && in1[i] == in2[0]) {
            var counter = 0;
            for (var j = 0; j < maxLen; j++) {
                if (i + j < in1_len && j < in2_len){
                    counter = in2[j] == in1[i + j] ? counter + 1 : 0;
                }
            }
            counter_max = counter_max < counter ? counter : counter_max;
        }
    }

    signal counterSignal;
    counterSignal <-- counter_max;

    log(counterSignal);
    log(in2_len);
    counterSignal === in2_len;
    
}

// component main = contains(8192, 2048);
