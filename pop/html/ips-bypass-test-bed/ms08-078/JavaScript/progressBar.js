var progressEnd = 9; // set to number of progress <span>'s.
var progressColor = '#3366CC'; // set to progress bar color
var progressInterval = 100; // set to time between updates (milli-seconds)

var progressAt = progressEnd;
var progressTimer;

function progressClear() {
	for (var i = 1; i <= progressEnd; i++) document.getElementById('progress'+i).style.backgroundColor = 'transparent';
	progressAt = 0;
}

function progressUpdate() {
	document.getElementById('showbar').style.visibility = 'visible';
	progressAt++;

	if (progressAt > progressEnd) progressClear();
	else document.getElementById('progress'+progressAt).style.backgroundColor = progressColor;

	progressTimer = setTimeout('progressUpdate()',progressInterval);
}

function progressStop() {
	clearTimeout(progressTimer);
	progressClear();
	document.getElementById('showbar').style.visibility = 'hidden';

}
