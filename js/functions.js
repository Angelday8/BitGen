let interval=600;
let process;

/**
 * Bitcoin Hunter START&STOP
 */
$(document).ready(function(){
    function generateAddress(){
        KherwaJS.getBitcoinAddress(1).then(function (objArray) {
            if (objArray && objArray[0].bitcoinAddr) {
                $('#address').html(objArray[0].bitcoinAddr);
                $('#public').html(objArray[0].pk)
                $('#wif').html(KherwaJS.privkeyToWIF(objArray[0].sk));
                $('#private').html(objArray[0].sk);
				$('#btcbal').html(objArray[0].balance);
            } else {
                throw new TypeError("Couldn't Generate Address");
            }
        });
    }

    //Start
    $('#run').on('click',function (){
        process=setInterval(generateAddress,interval);
    })

    //Stop
    $('#stop').on('click',function (){
        clearInterval(process);
    });

});
