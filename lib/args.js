var argv = require('argv');
var packageJson = require('../package.json');

var modules = [
  {
    mod: 'start',
    description: 'start '+ packageJson.name + ' as a daemon',
    options: [
      {
        name: 'interface',
        short: 'i',
        type: 'string',
        description: 'Network interface on which tool works',
        example: packageJson.name + ' start -i eth0 or --interface=eth0'
      },
      {
        name: 'hostdb',
        short: 'd',
        type: 'string',
        description: 'stores valid hosts in external file (absolute path)',
        example: packageJson.name + ' start -d host_file or --hostdb=host_file'
      },
      {
        name: 'log',
        short: 'l',
        type: 'string',
        description: 'generte logs in external files(absolute path)',
        example: packageJson.name + ' start -l log_file or --log=log_file'
      }
    ]
  },
  {
    mod: 'stop',
    description: 'stop '+ packageJson.name + ' daemon',
    options: []
  },
  {
    mod: 'status',
    description: 'get status of '+ packageJson.name + ' daemon',
    options: []
  }
]

function generateHelpDoc(){
  var helpDoc = packageJson.description + '\n\nUSAGE:\n\n';
	helpDoc += '\tsudo ' + packageJson.name + ' [action] [options]\n\n';
	helpDoc += 'actions:\n\n';

	for(var i=0; i<modules.length; i++){
		helpDoc += '\t' + modules[i].mod + '\t\t' + modules[i].description + '\n\n';

		if (modules[i].options.length !== 0) {
			helpDoc += '\t\toptions:\n';
		}

		for (var key2 in modules[i].options) {
			var option = modules[i].options[key2];
			helpDoc += '\t\t\t--' + option.name + ', -' + option.short + '\n';
			helpDoc += '\t\t\t\t' + option.description + '\n';
			helpDoc += '\t\t\t\t' + option.example + '\n\n';
		}

		helpDoc += '\n';
	}

	helpDoc += 'global options:';

	return helpDoc;
}

argv.version(packageJson.version);
for(var i=0; i<modules.length; i++){
  argv.mod(modules[i]);
}
argv.info(generateHelpDoc());

var args = argv.run();

var params = {};

params.log = typeof args.options.log === 'undefined' ? false : args.options.log;
params.hostdb = typeof args.options.hostdb === 'undefined' ? false : args.options.hostdb;
params.iface = typeof args.options.interface === 'undefined' ? false : args.options.interface;
if(args.mod == 'start'){
  if((params.iface !== false) && (params.hostdb !== false)) params.command = args.mod;
}else params.command = args.mod;

exports.params = params;

exports.help = argv.help;
