/********************
 * Planet Mandriva
 * stylesheet switcher
 * based on http://www.alistapart.com/articles/alternate/
 * May 2005
 * by John Keller
 * www.johnkeller.com
 ********************/


// stylesheet utility functions
function setActiveStyleSheet(title) {
	var linkArray = document.getElementsByTagName("link");

	for (var i = 0; (i < linkArray.length); i++) {
		var linkObj = linkArray[i];

		if ((linkObj.getAttribute("rel").indexOf("style") != -1)
				&& linkObj.getAttribute("title"))
		{
			// the first setting is necessary for IE and other browsers
			linkObj.disabled = true;
			linkObj.disabled = (linkObj.getAttribute("title") != title);
		}
	}

	var expireTime = new Date();
	expireTime.setTime(expireTime.getTime() + 120 * 24 * 60 * 60 * 1000);

	setCookie("style", title, expireTime);
}

function getActiveStyleSheet() {
	var styleName = null;
	var linkArray = document.getElementsByTagName("link");

	for (var i = 0; (i < linkArray.length); i++) {
		var linkObj = linkArray[i];

		if ((linkObj.getAttribute("rel").indexOf("style") != -1)
				&& linkObj.getAttribute("title")
				&& !linkObj.disabled)
		{
			styleName = linkObj.getAttribute("title");
			break;
		}
	}

	return styleName;
}

function getPreferredStyleSheet() {
	var styleName = null;

	var linkArray = document.getElementsByTagName("link");

	for (var i = 0; (i < linkArray.length); i++) {
		var linkObj = linkArray[i];

		if ((linkObj.getAttribute("rel").indexOf("style") != -1)
				&& linkObj.getAttribute("title")
				&& (linkObj.getAttribute("rel").indexOf("alt") == -1))
		{
			styleName = linkObj.getAttribute("title");
			break;
		}
	}

	return styleName;
}


// cookie utility functions
function _cookie(name) {
	var cookieValue, search;

	cookieValue = null;
	search = name + "=";

	if (document.cookie.length > 0) {
		offset = document.cookie.indexOf(search);
		if (offset != -1) {
			offset += search.length;
			end = document.cookie.indexOf(";", offset);
			if (end == -1) {
				end = document.cookie.length;
			}
			cookieValue = unescape(document.cookie.substring(offset, end));
		}
	}

	return cookieValue;
}

function setCookie(name, value, expire, domain, path) {
	document.cookie = name + "=" + escape(value)
		+ ((domain) ? "; domain=" + domain : "")
		+ "; path=" + ((path) ? path : "/")
		+ ((expire) ? "; expires=" + expire.toGMTString() : "");
}

function unsetCookie(name, domain, path) {
	if (_cookie(name)) {
		setCookie(name, "", new Date(0), domain, path);
	}
}


// dual-purpose init
function init() {
	var cookie = _cookie("style");
	var title = (cookie ? cookie : getPreferredStyleSheet());

	setActiveStyleSheet(title);
}

// at load, select current stylesheet
// (the "nice" way)
window.onload = init;

// force current stylesheet
// before initial render
init();
