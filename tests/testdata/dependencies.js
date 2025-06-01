/**
 * Sample JavaScript file with various dependencies
 * Used for testing dependency extraction
 */

// ES Module imports
import React, { useState, useEffect } from 'react';
import ReactDOM from 'react-dom';
import PropTypes from 'prop-types';
import { Route, Switch, Link } from 'react-router-dom';
import { connect } from 'react-redux';
import { createSelector } from 'reselect';
import styled from 'styled-components';
import axios from 'axios';
import * as d3 from 'd3';
import _ from 'lodash';
import moment from 'moment';

// CommonJS require
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const zlib = require('zlib');
const util = require('util');
const child_process = require('child_process');

// Named requires
const { readFile } = require('fs/promises');
const { v4: uuidv4 } = require('uuid');

// Dynamic imports
import('./dynamicModule.js').then(module => {
  console.log('Dynamic module loaded', module);
});

// Import with alias
import { default as MyComponent } from './components/MyComponent';

// Webpack specific imports
require.context('./components/', true, /\.jsx$/);
require.ensure(['jquery'], function(require) {
  const $ = require('jquery');
});

// Create app
const app = express();

// Component with dependencies
function MyApp() {
  const [data, setData] = useState(null);
  
  useEffect(() => {
    axios.get('/api/data')
      .then(response => {
        setData(_.groupBy(response.data, 'category'));
      })
      .catch(error => {
        console.error('Error fetching data:', error);
      });
  }, []);
  
  return (
    <div>
      <h1>Dependency Example</h1>
      {data && (
        <ul>
          {Object.keys(data).map(key => (
            <li key={key}>
              <strong>{key}:</strong> {data[key].length} items
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

// Export for module use
export default MyApp; 