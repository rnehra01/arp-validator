var fs = require('fs');
var notifier = require('node-notifier');
var args = require('./args.js');

var logFile = args.params.log;

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
