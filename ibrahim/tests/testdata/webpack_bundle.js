/*!
 * Sample Webpack Bundle
 * This is a simulated webpack bundle for testing
 */
(function(modules) {
	// webpackBootstrap
	var installedModules = {};
	function __webpack_require__(moduleId) {
		if(installedModules[moduleId]) {
			return installedModules[moduleId].exports;
		}
		var module = installedModules[moduleId] = {
			i: moduleId,
			l: false,
			exports: {}
		};
		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
		module.l = true;
		return module.exports;
	}
	__webpack_require__.m = modules;
	__webpack_require__.c = installedModules;
	__webpack_require__.d = function(exports, name, getter) {
		if(!__webpack_require__.o(exports, name)) {
			Object.defineProperty(exports, name, { enumerable: true, get: getter });
		}
	};
	__webpack_require__.r = function(exports) {
		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
		}
		Object.defineProperty(exports, '__esModule', { value: true });
	};
	__webpack_require__.t = function(value, mode) {
		if(mode & 1) value = __webpack_require__(value);
		if(mode & 8) return value;
		if((mode & 4) && typeof value === 'object' && value && value.__esModule) return value;
		var ns = Object.create(null);
		__webpack_require__.r(ns);
		Object.defineProperty(ns, 'default', { enumerable: true, value: value });
		if(mode & 2 && typeof value != 'string') for(var key in value) __webpack_require__.d(ns, key, function(key) { return value[key]; }.bind(null, key));
		return ns;
	};
	__webpack_require__.n = function(module) {
		var getter = module && module.__esModule ?
			function getDefault() { return module['default']; } :
			function getModuleExports() { return module; };
		__webpack_require__.d(getter, 'a', getter);
		return getter;
	};
	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
	__webpack_require__.p = "";
	return __webpack_require__(__webpack_require__.s = 0);
})({
	0: function(module, exports, __webpack_require__) {
		module.exports = __webpack_require__(1);
	},
	1: function(module, exports, __webpack_require__) {
		"use strict";
		Object.defineProperty(exports, "__esModule", { value: true });
		var react_1 = __webpack_require__(2);
		var react_dom_1 = __webpack_require__(3);
		var App_1 = __webpack_require__(4);
		var axios_1 = __webpack_require__(5);
		var lodash_1 = __webpack_require__(6);
		
		// Sample application entry point
		react_dom_1.default.render(react_1.default.createElement(App_1.default, null), document.getElementById('root'));
		
		// Sample API request
		axios_1.default.get('https://api.example.com/data')
			.then(function(response) {
				console.log(lodash_1.default.get(response, 'data', {}));
			})
			.catch(function(error) {
				console.error('API Error:', error);
			});
	},
	2: function(module, exports) {
		module.exports = React;
	},
	3: function(module, exports) {
		module.exports = ReactDOM;
	},
	4: function(module, exports, __webpack_require__) {
		"use strict";
		Object.defineProperty(exports, "__esModule", { value: true });
		var react_1 = __webpack_require__(2);
		
		// Sample App component
		function App() {
			var _a = react_1.useState('Hello SpiderJS'), message = _a[0], setMessage = _a[1];
			react_1.useEffect(function() {
				var timer = setTimeout(function() {
					setMessage('Webpack bundle analyzed!');
				}, 2000);
				return function() { clearTimeout(timer); };
			}, []);
			
			return react_1.default.createElement("div", { className: "app" },
				react_1.default.createElement("h1", null, message),
				react_1.default.createElement("p", null, "This is a sample webpack bundle for testing purposes.")
			);
		}
		
		exports.default = App;
	},
	5: function(module, exports) {
		module.exports = axios;
	},
	6: function(module, exports) {
		module.exports = _;
	}
}); 