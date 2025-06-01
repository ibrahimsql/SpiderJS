/*!
 * Sample Rollup Bundle
 * This is a simulated rollup bundle for testing
 */
(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
  typeof define === 'function' && define.amd ? define(['exports'], factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, factory(global.SpiderJSTest = {}));
})(this, (function (exports) { 'use strict';

  // Utility functions
  function isObject(value) {
    return value !== null && typeof value === 'object';
  }

  function isFunction(value) {
    return typeof value === 'function';
  }

  function isString(value) {
    return typeof value === 'string';
  }

  // Simple component system
  function Component(props) {
    this.props = props || {};
    this.state = {};
  }

  Component.prototype.setState = function(newState) {
    this.state = Object.assign({}, this.state, newState);
    this.render();
  };

  Component.prototype.render = function() {
    throw new Error('Component must implement render method');
  };

  // API client
  var ApiClient = {
    baseUrl: 'https://api.example.com',
    
    get: function(endpoint) {
      return fetch(this.baseUrl + endpoint)
        .then(function(response) {
          return response.json();
        });
    },
    
    post: function(endpoint, data) {
      return fetch(this.baseUrl + endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
      }).then(function(response) {
        return response.json();
      });
    }
  };

  // Application class
  function App() {
    Component.call(this);
    this.state = {
      data: null,
      loading: true,
      error: null
    };
  }

  App.prototype = Object.create(Component.prototype);
  App.prototype.constructor = App;

  App.prototype.fetchData = function() {
    var self = this;
    ApiClient.get('/data')
      .then(function(data) {
        self.setState({ data: data, loading: false });
      })
      .catch(function(error) {
        self.setState({ error: error, loading: false });
      });
  };

  App.prototype.render = function() {
    var content;
    if (this.state.loading) {
      content = 'Loading...';
    } else if (this.state.error) {
      content = 'Error: ' + this.state.error.message;
    } else {
      content = 'Data loaded: ' + JSON.stringify(this.state.data);
    }
    
    document.getElementById('app').textContent = content;
  };

  // Export public API
  exports.Component = Component;
  exports.ApiClient = ApiClient;
  exports.App = App;
  exports.utils = {
    isObject: isObject,
    isFunction: isFunction,
    isString: isString
  };

  Object.defineProperty(exports, '__esModule', { value: true });

}));