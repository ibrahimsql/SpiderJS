/*! For license information please see webpack_bundle.js.LICENSE.txt */
(() => {
  "use strict";
  var __webpack_modules__ = {
    "./src/index.js": (
      __unused_webpack_module,
      __webpack_exports__,
      __webpack_require__
    ) => {
      __webpack_require__.r(__webpack_exports__);
      var _api__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("./src/api.js");
      var react__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__("./node_modules/react/index.js");
      var axios__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__("./node_modules/axios/index.js");

      // Main application code
      const App = () => {
        const [data, setData] = react__WEBPACK_IMPORTED_MODULE_1__.useState(null);
        
        react__WEBPACK_IMPORTED_MODULE_1__.useEffect(() => {
          (0, _api__WEBPACK_IMPORTED_MODULE_0__.fetchData)()
            .then(response => setData(response))
            .catch(err => console.error(err));
        }, []);
        
        return react__WEBPACK_IMPORTED_MODULE_1__.createElement(
          "div",
          null,
          data ? 
            react__WEBPACK_IMPORTED_MODULE_1__.createElement("pre", null, JSON.stringify(data, null, 2)) : 
            react__WEBPACK_IMPORTED_MODULE_1__.createElement("p", null, "Loading...")
        );
      };
      
      react__WEBPACK_IMPORTED_MODULE_1__.render(
        react__WEBPACK_IMPORTED_MODULE_1__.createElement(App, null),
        document.getElementById("root")
      );
    },
    "./src/api.js": (
      __unused_webpack_module,
      __webpack_exports__,
      __webpack_require__
    ) => {
      __webpack_require__.r(__webpack_exports__);
      __webpack_require__.d(__webpack_exports__, {
        fetchData: () => fetchData
      });
      var axios__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__("./node_modules/axios/index.js");
      
      const API_ENDPOINT = "https://api.example.com/data";
      
      const fetchData = async () => {
        try {
          const response = await axios__WEBPACK_IMPORTED_MODULE_0__.default.get(API_ENDPOINT);
          return response.data;
        } catch (error) {
          console.error("API error:", error);
          throw error;
        }
      };
    }
  };
  
  // Webpack runtime code
  var __webpack_module_cache__ = {};
  
  function __webpack_require__(moduleId) {
    var cachedModule = __webpack_module_cache__[moduleId];
    if (cachedModule !== undefined) {
      return cachedModule.exports;
    }
    var module = __webpack_module_cache__[moduleId] = {
      exports: {}
    };
    __webpack_modules__[moduleId](module, module.exports, __webpack_require__);
    return module.exports;
  }
  
  __webpack_require__.d = (exports, definition) => {
    for(var key in definition) {
      if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
        Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
      }
    }
  };
  
  __webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop));
  
  __webpack_require__.r = (exports) => {
    if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
      Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
    }
    Object.defineProperty(exports, '__esModule', { value: true });
  };
  
  // Initialize entry module execution
  __webpack_require__("./src/index.js");
})(); 