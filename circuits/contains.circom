pragma circom 2.0.3;


template contains(msgLen, bhLen) {
    
    // var msgLen = 4;
    // var bhLen = 3;
    signal input bh[bhLen];
    signal input msg[msgLen];
    
    var counter = 0;
    var counter_max = 0;
    for (var i = 0; i < msgLen; i++) {
        for (var j = 0; j < bhLen; j++) {
            if (i + j < msgLen){
                counter = bh[j] == msg[i + j] ? counter + 1 : 0;
            }
        }   
        counter_max = counter_max < counter ? counter : counter_max;
    }
    counter_max = counter_max > bhLen ? bhLen : counter_max;

    signal counterSignal;
    counterSignal <-- counter_max;
    counterSignal === bhLen;
    
}

// component main = contains(8192, 2048);
