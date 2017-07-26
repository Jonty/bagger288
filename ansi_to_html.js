var fs = require('fs');
var AU = require('ansi_up');

fs.readFile(process.argv[2], 'utf8', function (err, ansi_txt) {
	if (err) {
		return console.log(err);
	}
	var ansi_up = new AU.default;
	var html = ansi_up.ansi_to_html(ansi_txt);
	process.stdout.write('<pre style="line-height: 1.3; padding:1em; background: black; color: lightgray;">' + html + '</pre>');
});
