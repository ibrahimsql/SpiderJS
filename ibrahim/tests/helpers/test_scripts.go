package helpers

// GetWebpackScript returns a sample webpack bundle for testing
func GetWebpackScript() string {
	return `
(function(modules) {
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
})([
	(function(module, exports, __webpack_require__) {
		"use strict";
		__webpack_require__.r(exports);
		/* harmony import */ var react__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(1);
		/* harmony import */ var react_dom__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(2);
		/* harmony import */ var axios__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(3);
		
		function App() {
			const [data, setData] = Object(react__WEBPACK_IMPORTED_MODULE_0__["useState"])([]);
			
			Object(react__WEBPACK_IMPORTED_MODULE_0__["useEffect"])(() => {
				axios__WEBPACK_IMPORTED_MODULE_2__["default"].get('/api/data')
					.then(response => {
						setData(response.data);
						document.getElementById('result').innerHTML = response.data.message;
					})
					.catch(error => {
						console.error('Error fetching data:', error);
						eval("console.log('Error details:', error)");
					});
			}, []);
			
			return react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(
				'div',
				null,
				react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement('h1', null, 'My App'),
				react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement('ul', null, 
					data.map(item => react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement('li', { key: item.id }, item.name))
				)
			);
		}
		
		react_dom__WEBPACK_IMPORTED_MODULE_1__["default"].render(
			react__WEBPACK_IMPORTED_MODULE_0__["default"].createElement(App, null),
			document.getElementById('root')
		);
	})
]);`
}

// GetRollupScript returns a sample rollup bundle for testing
func GetRollupScript() string {
	return `
(function (global, factory) {
	typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('react'), require('react-dom')) :
	typeof define === 'function' && define.amd ? define(['exports', 'react', 'react-dom'], factory) :
	(global = global || self, factory(global.MyApp = {}, global.React, global.ReactDOM));
}(this, (function (exports, React, ReactDOM) { 'use strict';
	
	React = React && Object.prototype.hasOwnProperty.call(React, 'default') ? React['default'] : React;
	ReactDOM = ReactDOM && Object.prototype.hasOwnProperty.call(ReactDOM, 'default') ? ReactDOM['default'] : ReactDOM;
	
	function App() {
		const [data, setData] = React.useState([]);
		
		React.useEffect(() => {
			fetch('/api/data')
				.then(response => response.json())
				.then(data => {
					setData(data);
					document.write(JSON.stringify(data));
				})
				.catch(error => {
					console.error('Error fetching data:', error);
					setTimeout("console.log('Error details:', error)", 1000);
				});
		}, []);
		
		return React.createElement(
			'div',
			null,
			React.createElement('h1', null, 'My ROLLUP_CHUNK_ID App'),
			React.createElement('ul', null, 
				data.map(item => React.createElement('li', { key: item.id }, item.name))
			)
		);
	}
	
	ReactDOM.render(
		React.createElement(App, null),
		document.getElementById('root')
	);
	
	exports.App = App;
	
	Object.defineProperty(exports, '__esModule', { value: true });
	
})));`
}

// GetViteScript returns a sample Vite bundle for testing
func GetViteScript() string {
	return `
(function () {
    'use strict';

    var react = require('react');
    var client = require('react-dom/client');
    
    function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }
    
    var react__default = /*#__PURE__*/_interopDefaultLegacy(react);
    
    function App() {
        const [count, setCount] = react.useState(0);
        
        react.useEffect(() => {
            const handleMessage = (event) => {
                if (event.data && event.data.type === 'VITE_HMR_UPDATE') {
                    console.log('HMR update received');
                }
            };
            
            window.addEventListener('message', handleMessage);
            return () => window.removeEventListener('message', handleMessage);
        }, []);
        
        return react__default['default'].createElement(
            'div',
            null,
            react__default['default'].createElement('h1', null, 'Vite + React'),
            react__default['default'].createElement(
                'button',
                { onClick: () => setCount(count => count + 1) },
                'Count is: ',
                count
            )
        );
    }
    
    const root = client.createRoot(document.getElementById('root'));
    root.render(react__default['default'].createElement(App, null));
})();`
}

// GetAngularScript returns a sample Angular bundle for testing
func GetAngularScript() string {
	return `
(function (global, factory) {
    typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports, require('@angular/core')) :
    typeof define === 'function' && define.amd ? define(['exports', '@angular/core'], factory) :
    (global = global || self, factory(global.app = {}, global.ng.core));
}(this, (function (exports, core) { 'use strict';
    
    var AppComponent = /** @class */ (function () {
        function AppComponent() {
            this.title = 'my-app';
            this.items = [];
        }
        
        AppComponent.prototype.ngOnInit = function () {
            var _this = this;
            fetch('/api/items')
                .then(function (response) { return response.json(); })
                .then(function (data) {
                    _this.items = data;
                })
                .catch(function (error) {
                    console.error('Error fetching items:', error);
                });
        };
        
        AppComponent.ɵfac = function AppComponent_Factory(t) { return new (t || AppComponent)(); };
        AppComponent.ɵcmp = core.ɵɵdefineComponent({
            type: AppComponent,
            selectors: [["app-root"]],
            decls: 5,
            vars: 1,
            template: function AppComponent_Template(rf, ctx) {
                if (rf & 1) {
                    core.ɵɵelementStart(0, "div");
                    core.ɵɵelementStart(1, "h1");
                    core.ɵɵtext(2, "Welcome to ");
                    core.ɵɵtext(3, ctx.title);
                    core.ɵɵelementEnd();
                    core.ɵɵelementEnd();
                }
            }
        });
        return AppComponent;
    }());
    
    exports.AppComponent = AppComponent;
    
    Object.defineProperty(exports, '__esModule', { value: true });
    
})));`
}

// GetVulnerableScript returns a script with common security vulnerabilities for testing
func GetVulnerableScript() string {
	return `
// This script contains intentional security vulnerabilities for testing
function processUserInput(input) {
    // XSS vulnerabilities
    document.getElementById('output').innerHTML = input; // DOM XSS
    document.write(input); // document.write XSS
    
    // Code injection vulnerabilities
    eval(input); // eval injection
    new Function(input)(); // Function constructor injection
    setTimeout(input, 1000); // setTimeout with string argument
    
    // Prototype pollution
    const obj = {};
    const parts = input.split('.');
    let current = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        if (!current[parts[i]]) current[parts[i]] = {};
        current = current[parts[i]];
    }
    current[parts[parts.length - 1]] = 'polluted';
    
    // Insecure randomness
    const randomValue = Math.random() * 1000;
    const token = 'token_' + randomValue;
    
    // Insecure postMessage
    window.postMessage(input, '*');
    
    // CSRF vulnerability
    const form = document.createElement('form');
    form.action = '/api/update';
    form.method = 'POST';
    document.body.appendChild(form);
    form.submit();
    
    return obj;
}

// JWT handling
function decodeJWT(token) {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    try {
        return {
            header: JSON.parse(atob(parts[0])),
            payload: JSON.parse(atob(parts[1])),
            signature: parts[2]
        };
    } catch (e) {
        console.error('Error decoding JWT:', e);
        return null;
    }
}

// Fetch API with sensitive information
async function fetchUserData() {
    const apiKey = 'sk_test_51LNx0jKFbkT7YgV9';
    const response = await fetch('/api/user', {
        headers: {
            'Authorization': 'Bearer ' + apiKey,
            'Content-Type': 'application/json'
        }
    });
    return response.json();
}

// AWS credentials hardcoded
const awsConfig = {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    region: 'us-west-2'
};
`
}

// GetMinifiedScript returns a minified script for testing
func GetMinifiedScript() string {
	return `!function(e){var t={};function n(r){if(t[r])return t[r].exports;var o=t[r]={i:r,l:!1,exports:{}};return e[r].call(o.exports,o,o.exports,n),o.l=!0,o.exports}n.m=e,n.c=t,n.d=function(e,t,r){n.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:r})},n.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},n.t=function(e,t){if(1&t&&(e=n(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var r=Object.create(null);if(n.r(r),Object.defineProperty(r,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var o in e)n.d(r,o,function(t){return e[t]}.bind(null,o));return r},n.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return n.d(t,"a",t),t},n.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},n.p="",n(n.s=0)}([function(e,t,n){"use strict";n.r(t);var r=n(1),o=n(2);function i(){var e=Object(r.useState)([]),t=e[0],n=e[1];return Object(r.useEffect)((function(){o.a.get("/api/users").then((function(e){n(e.data)})).catch((function(e){console.error("Error:",e)}))})),r.createElement("div",null,r.createElement("h1",null,"Users"),r.createElement("ul",null,t.map((function(e){return r.createElement("li",{key:e.id},e.name)}))))}r.render(r.createElement(i,null),document.getElementById("app"))}]);`
}
