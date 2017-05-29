var loadScript = function(url, callback) {
	var _script = document.createElement("script");
	_script.setAttribute("type", "text/javascript");
	_script.setAttribute("src", url);
	_script.setAttribute("async", true);
	document.getElementsByTagName("head")[0].appendChild(_script);
	if (_script.readyState) {
		// IE
		_script.onreadystatechange = function() {
			if (_script.readyState == "loaded" || _script.readyState == "complete") {
				_script.onreadystatechange = null;
				if (callback) {
					callback();
				}
			}
		}
	} else {
		// 非IE
		_script.onload = function() {
			if (callback) {
				callback();
			}
		}
	}
};