/* The (relative) URL where the user's data is located. You should not need to use this directly. */
var url = "../cdn/data.enc";

/* The salt used to derive a key from the user's password. */
var salt = "8a4785891590ea6a43b858d73af65f12f3376947d0717585dead654457ceecf0";

/* The IV that was used to encrypt the user's data */
var iv = new Uint8Array([0x72, 0x0d, 0x30, 0x32, 0x5a, 0xda, 0x6c, 0x56, 0xcc, 0x1c, 0x2d, 0xd4]);

/* The Merkle tree. merkle_root is the root of the tree, and merkle_tree contains the Merkle path.
 * merkle_tree[0] is a leaf node, merkle_tree[1] is one level up, etc. 
 *
 *                               merkle_root
 *                                 +     +
 *                                 |     |
 *                       <---------+     +--------->
 *                   [compute]               merkle_tree[2]
 *                     +   +
 *                <----+   +------->
 *            [compute]      merkle_tree[1]
 *              +   +
 *     <--------+   +------>
 * SHA256(data)      merkle_tree[0]
 *
 * */
var merkle_root = '2c53caff52f43b08b34e105ae67d8c33f0b33a297db7f749ff1b2a6deb646041';
var merkle_tree = ['8e86c8a733ce58e68e01a24a271f961346a4437584eec89f39bb0f3246b7759b',
        '5f08975093846d9f49e8bb7808672305b8e7824f410075f2a36b2c8acc072d12',
        '73ad4bcfc747f04d8d92d5ba3c9b0e7d678775b2df618bff0a2f700b20673cb5'];

var hashedPwd;
var aryToUse;
var keyToUse;
var passwordEntered = function()
{
    var password = document.getElementById('password').value;
    var ary = lib.hexToArrayBuffer(password);
    lib.sha256Hash(ary).then(function(result){
       var input = result;
        if(lib.arrayBufferToHex(input) != "d188f7fe1ef021a4a9fde3862624fcc86ed39b0eb4a0490102f6756ceaa70ba9")
        {
            alert("Not valid password");

        }
        else
        {

            var hashData;
            var firstCompute;
            var secondCompute;
            var thirdCompute;

            /* Loads the encrypted data */
            var data;
            lib.getData(url).then(function(arr) {
                data = arr;
                lib.sha256Hash(data).then(function(hashedData){
                    hashData = hashedData;
                    firstCompute = lib.arrayBufferToHex(hashData) + merkle_tree[0];
                    var secondSha = lib.hexToArrayBuffer(firstCompute);
                    lib.sha256Hash(secondSha).then(function(ans2){
                        secondCompute = ans2;
                        var secondHash = lib.arrayBufferToHex(secondCompute);
                        var secondShaInput = secondHash + merkle_tree[1];
                        var secondShaArray = lib.hexToArrayBuffer(secondShaInput);
                        lib.sha256Hash(secondShaArray).then(function(ans3){
                            thirdCompute = ans3;
                            var thirdString = lib.arrayBufferToHex(thirdCompute);
                            var thirdSha = thirdString + merkle_tree[2];
                            var finalArray = lib.hexToArrayBuffer(thirdSha);
                            lib.sha256Hash(finalArray).then(function(ans4){

                                var finalString = lib.arrayBufferToHex(ans4);
                                if(finalString == merkle_root)
                                {
                                    console.log("They match!");
                                    lib.balloonHash(password, salt).then(function(ans)
                                        {
                                            hashedPwd = ans;
                                            aryToUse = hashedPwd.subarray(0,32);
                                            console.log(ans);
                                            lib.importKey(aryToUse).then(function(rslt)
                                            {
                                                keyToUse= rslt;
                                                lib.decrypt(keyToUse, data, iv).then(function(ans){
                                                    var decryptedResult = ans;
                                                    displayImage(decryptedResult);
                                                });

                                            });
                                        }
                                    );
                                }
                                else
                                {
                                    console.log("Nope, screwed up");
                                }
                            });
                        });
                    });

                });

            });
        }
    });

};


/* Displays the decrypted image */
/* Source: https://jsfiddle.net/Jan_Miksovsky/yy7Zs/ */
var displayImage = function(arraybuffer) {
    var view = new Int8Array(arraybuffer);
    var blob = new Blob([view], { type: "image/png" });
    var urlCreator = window.URL || window.webkitURL;
    var imageUrl = urlCreator.createObjectURL(blob);
    var img = document.createElement("img");
    img.src = imageUrl;
    document.getElementById("photos").appendChild(img);
};
