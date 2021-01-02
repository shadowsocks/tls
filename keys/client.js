var fs = require('fs'); 
var https = require('https');
var options = {
    hostname: 'localhost', 
    port: 8000, 
    path: '/', 
    method: 'GET', 
    ca: [
        fs.readFileSync('./root.crt'),
        fs.readFileSync('./ca.crt'),
    ]
};
var req = https.request(options, function(res) { 
    res.on('data', function(data) { 
        process.stdout.write(data); 
    }); 
});

req.end();