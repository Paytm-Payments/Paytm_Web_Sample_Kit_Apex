public Class PaytmCheckSumUtil{

    public static String verifyCheckSum(String Key, Map<String,String> paramap, String ChecksumHash){

    List<String> lSort = new List<String>(paramap.keySet());
        lSort.sort();
        String response;
        for(String k : lSort){
            if(k != 'CHECKSUMHASH' ){
                if(response == null){
                    response = paramap.get(k);
                }
                else{
                     response = response + '|' + paramap.get(k);
                }
            }
        } 

        key = EncodingUtil.base64Encode(Blob.valueof(key)); 
        String iv1= EncodingUtil.base64Encode(Blob.valueof('@@@@&&&&####$$$$'));
        blob key1 = EncodingUtil.base64Decode(key);
        blob iv = EncodingUtil.base64Decode(iv1);
        
        blob encryptedData = EncodingUtil.base64Decode(ChecksumHash);        
        blob decryptedData = Crypto.decrypt('AES128', key1, iv, encryptedData);
        
        String hashValue = decryptedData .toString();
        String Salt = hashValue.right(4);
        response = response + '|' + Salt;
        String hashFromParams = '';
        Blob data = crypto.generateDigest('SHA-256', Blob.valueOf(response));
        hashFromParams = EncodingUtil.convertToHex(data);
        hashFromParams = hashFromParams+Salt;
        
        if (hashFromParams == hashValue){
            return 'true';
        }else{
            return 'false';
        }
    }  

    public static String genrateCheckSum(String Key, Map<String,String> paramap){
        List<String> lSort = new List<String>(paramap.keySet());
        lSort.sort();
        String response;
        for(String k : lSort){
            if(response == null){
                response = paramap.get(k);
            }
            else{
                 response = response + '|' + paramap.get(k);
            }
        }        

        Integer randomInt = 4;
        Blob blobKey1 = crypto.generateAesKey(128);
        String keyNew = EncodingUtil.convertToHex(blobKey1);
        String randomStr  = keyNew.substring(0,randomInt);
        response = response + '|' + randomStr;
        
        Blob data = crypto.generateDigest('SHA-256', Blob.valueOf(Response));
        String checkSumHash = EncodingUtil.base64Encode(data);
        checkSumHash = EncodingUtil.convertToHex(data);
        checkSumHash = checkSumHash + randomStr;
        key = EncodingUtil.base64Encode(Blob.valueof(key)); 
        String iv1= EncodingUtil.base64Encode(Blob.valueof('@@@@&&&&####$$$$')); 
        blob key1 = EncodingUtil.base64Decode(key);
        blob iv = EncodingUtil.base64Decode(iv1);
        blob textBlob = blob.valueOf(checkSumHash);
        blob encryptedData = Crypto.encrypt('AES128', key1, iv, textBlob);
        String checkSumValue = EncodingUtil.base64Encode(encryptedData);  
        if(checkSumValue != null){
            checkSumValue = checkSumValue.replaceAll('\r\n','');
            checkSumValue = checkSumValue.replaceAll('\r','');
            checkSumValue = checkSumValue.replaceAll('\n','');
        }
        return checkSumValue;
    } 
}