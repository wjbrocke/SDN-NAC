<?php
function xmlrpcClient($url, $request) {
  
    $header[] = "Content-type: text/xml";
    $header[] = "Content-length: ".strlen($request);
    
    $ch = curl_init($url);   
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $header);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $request);
    
    return trim(curl_exec($ch));
}

function getMAC($ip){
    $client = $ip;
    $result = `/sbin/arp -n $client`;

    $table = explode("\n",$result);
    foreach($table as $entry){
        if(preg_match("/$client\s+ether\s+([0-9A-Fa-f:]+)/",$entry,$matches)){
            return $matches[1];
        }
    }
}

function permitClient($username,$client_mac,$client_ip=""){

    $request = xmlrpc_encode_request('pClient', array($username,$client_mac,$client_ip));
    $response = xmlrpcClient("http://152.1.5.245:8000",$request);
    return $response;
}

?>
