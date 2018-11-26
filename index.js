let Cap = require('cap').Cap,
	decoders = require('cap').decoders,
	PROTOCOL = decoders.PROTOCOL;

let Tofhue = require('tofhue');


let action = function() {

	for (let i = 1; i <= 2; i++) {
		Tofhue.turnOffLight(i);
	}
};

let c = new Cap(),
	device = Cap.findDevice('192.168.1.25'),
	//Ez fontos, ez parameterezi a libpcap/winpcap filtereit.
	filter = 'arp',
	bufSize = 10 * 1024 * 1024,
	buffer = new Buffer(65535);

let linkType = c.open(device, filter, bufSize, buffer);

c.setMinBytes && c.setMinBytes(0);

c.on('packet', function(nbytes, trunc) {
	//console.log('packet: length ' + nbytes + ' bytes, truncated? ' + (trunc ? 'yes' : 'no'));

	// raw packet data === buffer.slice(0, nbytes)

	if (linkType === 'ETHERNET') {
		let ret = decoders.Ethernet(buffer);

		//Ez is fontos, kulonben nem a megfelelore matchelsz.
		if (ret.info.type === PROTOCOL.ETHERNET.ARP) {
			if (ret.info.srcmac.toString().toLowerCase() === "34:d2:70:b3:13:42") {
				console.log('Decoding ARP ...');
				action();
			}
		} else {
			console.log('Unsupported Ethertype: ' + PROTOCOL.ETHERNET[ret.info.type]);
		}
	}
});