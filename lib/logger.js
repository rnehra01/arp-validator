var fs = require('fs');
var notifier = require('node-notifier');

var logFile = process.argv[4];

function log(str, type){
  if(logFile !== undefined){
    fs.appendFileSync(logFile, str + '\n');
  }

  if(type !== 'debug'){
    notifier.notify({
      title: 'ARP Poisoning Detected!!!',
      message: str
    });
  }
}

exports.log = log;
