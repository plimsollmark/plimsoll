// Tries the network: a TCP connection to a documentation address, a DNS lookup, a UDP packet.
const net = require('net'), dns = require('dns'), dgram = require('dgram');
const s = net.connect({ host: '203.0.113.7', port: 443 });
s.on('error', () => {});
dns.lookup('canary.example', () => {});
const u = dgram.createSocket('udp4');
u.send(Buffer.from('hi'), 53, '198.51.100.9', () => u.close());
setTimeout(() => { s.destroy(); process.exit(0); }, 500);
