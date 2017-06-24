var sleep = require('sleep');
var os = require('os')
var ip = require('ip');
var arrayCounter = require('array-counter');
var raw = require ("raw-socket");



/**********  Necesary[0] functions to uncrypt the payload ************/

function hexToDec(hex) {
	var result = 0, digitValue;
	hex = hex.toLowerCase();
	for (var i = 0; i < hex.length; i++) {
		digitValue = '0123456789abcdefgh'.indexOf(hex[i]);
		result = result * 16 + digitValue;
	}
	return result;
}


function getIp(getip){
	var ip = "";
	for(var i = 0;i<getip.length;i+=2){
		ip += hexToDec(getip.substr(i,2)).toString();
		if(i != (getip.length)-2){
			ip += ".";
		}
	}
	return ip;
}




/**********  END NECESARY[0] FUNCTIONS ************/

/* CONVERT FLAGS */
function convert(dec){
	var final = [];
	let pseflags = {128:"CWR" , 64:"ECE" , 32:"URG" , 16:"ACK", 8:"PSH" , 4:"RST" , 2:"SYN" , 1:"FIN"};
	var numbers = [128,64,32,16,8,4,2,1];
	for(i in numbers){
		if(dec >= numbers[i]){
			dec = dec - numbers[i];
			final.push(pseflags[numbers[i]]);
		}
	}
	return final;
}

/* End Parsing  flags */



var blacklist = [];
var fullscandb = {};
var halfscandb = {};
var xmasscandb = {};
var nullscandb = {};
var finscandb = {};
var waiting = [];
var threewayhandshake = [];
var scannedports = {};

var data,dataforthreewaycheck,dbdata,reverse;

var lanip = ip.address() // my lanip


function count(array,single){
	var count = 0;
	for(var i = 0; i < array.length; ++i){
		if(array[single])
			count++;
	}
}



function threewaycheck(sip,dip,sport,dport,seqnum,acknum,flags){
	data = sip+":"+ sport +"->"+dip+":"+dport+"_"+seqnum+"_"+acknum+"_"+flags.join("/");
	
	if(flags.indexOf("SYN") >= 0 && flags.length == 1){
		if(seqnum > 0 && acknum === 0){
			waiting.push(seqnum+"_"+acknum+"_"+sip+":"+sport+"->"+dip+":"+dport);
		}
	}
	else if (flags.indexOf("SYN") >= 0 && flags.indexOf("ACK") >= 0 && flags.length ==2){
		for(i in waiting){
			pieces = waiting[i].split("_");
			olseq = pieces[0];
			olack = pieces[1];

			if(parseInt(acknum) == parseInt(olseq)+1){
				var index = waiting.indexOf(waiting[i]);
				waiting.splice(index, 1);
				waiting.push(seqnum+"_"+acknum+"_"+sip+":"+sport+"->"+dip+":"+dport);
				break;
			}
		}
	}

	else if(flags.indexOf("ACK") >= 0 && flags.length==1){
		for(i in waiting){
			pieces = waiting[i].split("_");
			olseq = pieces[0];
			olack = pieces[1];
			if(seqnum == olack && parseInt(acknum) == parseInt(olseq)+1){
				var index = waiting.indexOf(waiting[i]);
				waiting.splice(index, 1);
				threewayhandshake.push(sip+":"+sport+"->"+dip+":"+dport);
				break;
			}
		}
	}
}



function scancheck(sip,dip,sport,dport,seqnum,acknum,flags){
	
	data = data = sip+":"+ sport +"->"+dip+":"+dport+"_"+seqnum+"_"+acknum+"_"+flags.join("/");
	dataforthreewaycheck = sip+":"+sport+"->"+dip+":"+dport;
	dbdata = sip+"->"+dip;
	reverse = dip+"->"+sip;
	if(halfconnectscan(sip,dip,sport,dport,seqnum,acknum,flags)){
		console.log("cumple if");
		returned = halfconnectscan(sip,dip,sport,dport,seqnum,acknum,flags);
		if(typeof(returned) == String){
			console.log(returned);
		}
		else 
			console.log(" Port Scanning: Attempt to conect a closed port " + dport + " from " + sip + "->" + sport);
	}


	else if(fullconnectscan(sip,dip,sport,dport,seqnum,acknum,flags)){
		returned = fullconnectscan(sip,dip,sport,dport,seqnum,acknum,flags);
		if(typeof(returned) == String){
			console.log(returned);
		}
		else
			console.log(" Port Scanning: Attempt to conect a closed port " + dport + " from " + sip + "->" + sport);
	}

	else if(xmasscan(sip,dip,sport,dport,seqnum,acknum,flags)){
		console.log("XMAS scan detected!");
	}
	else if(finscan(sip,dip,sport,dport,seqnum,acknum,flags)){
		console.log(" FIN scan detected!");
	}
	else if(nullscan(sip,dip,sport,dport,seqnum,acknum,flags)){
		console.log("NULL scan detected!");
	}

}



function fullconnectscan(sip,dip,sport,dport,seqnum,acknum,flags){

	if(scannedports[dip] != undefined){
		scannedports[dip].push(sport);
	} 
	else{
		scannedports[dip] = [];
		scannedports[dip].push(sport);
	} 

	if(dataforthreewaycheck in threewayhandshake){

		if(flags.indexOf("ACK") >= 0 && flags.indexOf("RST") >= 0 && flags.length == 2){
			if(fullscandb[dbdata] != undefined){
				counter = parseInt(fullscandb[dbdata]);
			}
			if(counter > 3){
				if(blacklist.indexOf(dip) < 0){
					blacklist.push(dip);
				}
				return "Full scan detected!";
			}
			else{
				counter++;
				fullscandb[dbdata] = String(counter);
			}
		}

	}

	else{
		if(flags.indexOf("SYN") >= 0 && flags.length == 1){
			//first connection
			if(seqnum>0 && acknum==0)
				halfscandb[dbdata+"_"+seqnum] = dbdata+"_SYN_ACK_"+seqnum+"_"+acknum;
		}
		else if(flags.indexOf("RST") >= 0 && flags.indexOf("ACK") >= 0 && flags.length == 2){
			if(fullscandb[String(dip+"->"+sip+"_SYN")]){
				manage = fullscandb[dip+"->"+sip+"_SYN"];
				pieces = manage.split("_");
				olack = parseInt(pieces[1]);
				olseq = parseInt(pieces[0]);
				if(seqnum == 0 && acknum == parseInt(olack)+1){
					if(fullscandb[dbdata]){
						counter = parseInt(fullscandb[dbdata]);
						if(counter > 3){
							if(blacklist.indexOf(dip) < 0 ){
								blacklist.push(dip);
							}
							return true;
						}
						else{
							counter++;
							fullscandb[dbdata] = String(counter);
						}
					}
					else{
						counter = 0;
						fullscandb[dbdata] = String(counter);
					}
				} 
			}
		}
	}
	return false;

}





function halfconnectscan(sip,dip,sport,dport,seqnum,acknum,flags){


	if(scannedports[dip] != undefined){
		scannedports[dip].push(sport);
	} 
	else{
		scannedports[dip] = [];
		scannedports[dip].push(sport);
	} 


	if(flags.indexOf("SYN") >= 0 && flags.length == 1 && seqnum>0 && acknum==0){
		//first connection
		halfscandb[dbdata+"_"+seqnum] = dbdata+"_SYN_ACK_"+seqnum+"_"+acknum;
	}

	else if(flags.indexOf("RST") >= 0 && flags.indexOf("ACK") >= 0 && flags.length == 2){
		// closing connection with RST, dirty close, add directionIP to blacklist connection
		if(halfscandb[reverse+"_"+String(acknum-1)] != undefined){
			delete halfscandb[reverse+"_"+String(acknum-1)];
			if(blacklist.indexOf(dip) < 0){
				blacklist.push(dip);
			}
			return true;
		}
	}
	else if(flags.indexOf("SYN") >= 0 && flags.indexOf("ACK") >= 0 && flags.length == 2){
		if(halfscandb[reverse+"_"+String(acknum-1)] != undefined){
			delete halfscandb[reverse+"_"+String(acknum-1)];
			halfscandb[reverse+"_"+String(acknum-1)] = dbdata+"_RST_"+seqnum+"_"+acknum;
		}
	}
	// if the server response with a rst, and any of the before ifs are true. Someone try to access to a restrict port! 
	else if(flags.indexOf("RST") >= 0 && flags.length == 1){
		if(halfscandb[dbdata+"_"+String(seqnum)] != undefined){
			if(blacklist.indexOf(dip) < 0){
				blacklist.push(dip);
			}
			return " => [Runtime Detection:] Half connect(SYN scan) scan detected!";
		}
	}
	return false;

};


function xmasscan(sip,dip,sport,dport,seqnum,acknum,flags) {
	if(scannedports[dip] != undefined){
		scannedports[dip].push(sport);
	} 
	else{
		scannedports[dip] = [];
		scannedports[dip].push(sport);
	} 
	if(flags.indexOf("FIN") >= 0 && flags.indexOf("URG") >= 0 flags.indexOf("PSH") >= 0 && flags.length == 3){
		if(blacklist.indexOf(sip) < 0 ){
			blacklist.push(sip);
		}
		return true;
	}
	return false;
}



function finscan(sip,dip,sport,dport,seqnum,acknum,flags){
	if(scannedports[dip] != undefined){
		scannedports[dip].push(sport);
	} 
	else{
		scannedports[dip] = [];
		scannedports[dip].push(sport);
	} 
	if(threewayhandshake.indexOf(dataforthreewaycheck) < 0){
		if(flags.indexOf("FIN") >= 0 && flags.length == 1){
			if(blacklist.indexOf(sip) < 0 ){
				blacklist.push(sip);
			}
			return true;
		}
	}
	return false;
}


function nullscan(sip,dip,sport,dport,seqnum,acknum,flags){
	if(scannedports[dip] != undefined){
		scannedports[dip].push(sport);
	} 
	else{
		scannedports[dip] = [];
		scannedports[dip].push(sport);
	}
	if(flags.length == 0){
		if(blacklist.indexOf(sip) < 0){
			blacklist.push(sip);
		}
		return true;
	}
	return false;
}



//MAIN
var socketTCP = raw.createSocket ({protocol: raw.Protocol.TCP});

socketTCP.on ("message", function (buffer, address) {
	// console.log ("TCP received " + buffer.length + " bytes from " + address
	// 	+ ": " + buffer.toString ("hex"));


	//IPV4
	var parsed = buffer.toString("hex"); /* the two start bytes are version and length */
	var version = parsed[0]; 
  	var length = (parsed[1] * 64)/16; //5 palabras (5x32 = 160 bits, 20 bytes) 
 	var sip = getIp(parsed.substr(24, 8)); // maybe I can extract the destination ip for cb address, but dont matter
 	var dip = getIp(parsed.substr(32,8));
 	// timestamp = time.time(); 
 	elave= undefined;


	//TCP 
	var sport = hexToDec(parsed.substr(40,4));
	var dport = hexToDec(parsed.substr(44,4));
	var seqnumb = hexToDec(parsed.substr(48,8));
	var ack = hexToDec(parsed.substr(56,8));
	var flags = convert(hexToDec(parsed.substr(66,2)));
	var testdata = sip+":"+sport+"->"+dip+":"+dport;
	
	if(threewayhandshake.indexOf(testdata) == -1){
		threewaycheck(sip,dip,sport,dport,seqnumb,ack,flags);
	}
	
	scancheck(sip,dip,sport,dport,seqnumb,ack,flags);
	console.log("\n\n");


});




