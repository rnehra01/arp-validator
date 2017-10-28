var args = require('./lib/args.js');
var packageJson = require('./package.json');
var fs = require('fs');

var daemon = require('daemonize2').setup({
	main: 'app.js',
	name: packageJson.name,
});

switch (args.params.command) {
	case 'start':
		daemon.start();
		break;

	case 'stop':
		daemon.stop();
		break;

	case 'status':
		var pid = daemon.status();
		if (pid) {
			console.log(packageJson.name + ' daemon running. PID: ' + pid);
		}
		else {
			console.log(packageJson.name + ' daemon not running.');
		}
		break;

	default:
		args.help();
}

process.on('uncaughtException', function(err) {
	fs.appendFile(args.params.log, err + '\n');
});
