/**
 * Sample Vulnerable JavaScript
 * This file contains various security vulnerabilities for testing
 */

// DOM-based XSS vulnerabilities
function displayUserInput(input) {
  // Direct innerHTML assignment - XSS vulnerability
  document.getElementById('output').innerHTML = input;
  
  // document.write - XSS vulnerability
  document.write('<div>' + input + '</div>');
  
  // jQuery HTML insertion - XSS vulnerability
  $('#output').html(input);
}

// JavaScript injection vulnerabilities
function executeUserCode(code) {
  // eval - Code injection vulnerability
  eval(code);
  
  // setTimeout with string - Code injection vulnerability
  setTimeout(code, 1000);
  
  // Function constructor - Code injection vulnerability
  new Function(code)();
  
  // setInterval with string - Code injection vulnerability
  setInterval(code, 2000);
}

// Prototype pollution vulnerability
function mergeObjects(target, source) {
  for (var key in source) {
    if (typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      mergeObjects(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// Insecure randomness
function generateToken() {
  return Math.random().toString(36).substring(2);
}

// Insecure hashing
function hashPassword(password) {
  var hash = 0;
  for (var i = 0; i < password.length; i++) {
    hash = ((hash << 5) - hash) + password.charCodeAt(i);
    hash |= 0;
  }
  return hash.toString();
}

// Path traversal vulnerability
function readUserFile(filename) {
  const fs = require('fs');
  return fs.readFileSync('/var/www/uploads/' + filename);
}

// SQL injection vulnerability
function getUserData(userId) {
  const db = require('./database');
  return db.query('SELECT * FROM users WHERE id = ' + userId);
}

// Insecure cookie
function setUserCookie(userId) {
  document.cookie = 'userId=' + userId + '; path=/';
}

// Insecure authentication
function login(username, password) {
  if (username === 'admin' && password === 'password123') {
    return { token: generateToken() };
  }
  return { error: 'Invalid credentials' };
}

// Export functions for testing
module.exports = {
  displayUserInput,
  executeUserCode,
  mergeObjects,
  generateToken,
  hashPassword,
  readUserFile,
  getUserData,
  setUserCookie,
  login
}; 