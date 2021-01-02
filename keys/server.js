const fs = require('fs');
const https = require('https');
const http2 = require('http2');


const options = {
    key: fs.readFileSync('./server.key'),
    cert: fs.readFileSync('./server.crt')
};
 
https.createServer(options, function(req, res) {
    res.writeHead(200);
    res.end('hello world');
}).listen(8001);


const server = http2.createSecureServer(options);
server.on('error', function (e) {
    console.log(e);
});
server.on('stream', (stream, headers) => {
    stream.respond({
        'content-type': 'text/html',
        ':status': 200
    });
    stream.end('<h1>Hello World</h1>');
});
server.listen(8000);
