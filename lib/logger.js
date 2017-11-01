var fs = require('fs');
var notifier = require('node-notifier');
var args = require('./args.js');

var logFile = args.params.log;
// The time to till which the notification will not display again
var TIME_LIMIT = 1000*60*60;
var notificationCache = {};

function log(str, type){
  if(logFile !== undefined){
    fs.appendFileSync(logFile, str + '\n');
  }

  if(type !== 'debug'){
    var time = new Date().getTime();
  	if(notificationCache.hasOwnProperty(str)) {
  		if((notificationCache[str]+TIME_LIMIT) >= time) {
  			// Don't display notification
  			return;
  		}
  	}

    notifier.notify({
      title: 'ARP Poisoning Detected!!!',
      message: str
    });

    notificationCache[str] = time;
  }
}

exports.log = log;
