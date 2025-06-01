package helpers

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ibrahimsql/spiderjs/internal/config"
	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
	"github.com/stretchr/testify/require"
)

// CreateTempFile creates a temporary file with the given content and returns its path
func CreateTempFile(t *testing.T, prefix string, content string) string {
	tempFile, err := ioutil.TempFile("", prefix)
	require.NoError(t, err, "Failed to create temp file")

	_, err = tempFile.WriteString(content)
	require.NoError(t, err, "Failed to write to temp file")

	err = tempFile.Close()
	require.NoError(t, err, "Failed to close temp file")

	return tempFile.Name()
}

// CreateTempDirectory creates a temporary directory and returns its path
func CreateTempDirectory(t *testing.T, prefix string) string {
	tempDir, err := ioutil.TempDir("", prefix)
	require.NoError(t, err, "Failed to create temp directory")
	return tempDir
}

// CreateTestTarget creates a test target with the given URL
func CreateTestTarget(t *testing.T, urlStr string) *models.Target {
	target, err := models.NewTarget(urlStr)
	require.NoError(t, err, "Failed to create target")
	return target
}

// CreateTestContext creates a test context with timeout
func CreateTestContext(t *testing.T) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 30*time.Second)
}

// CreateTestConfig creates a test configuration
func CreateTestConfig(t *testing.T) *config.Config {
	cfg := config.LoadDefaultConfig()
	require.NotNil(t, cfg, "Failed to load default config")
	return cfg
}

// CreateTestLogger creates a test logger
func CreateTestLogger(t *testing.T) *logger.Logger {
	log := logger.NewLogger()
	require.NotNil(t, log, "Failed to create logger")
	return log
}

// CreateTestStructure creates a test directory structure with the given files
// files is a map of file paths to file contents
func CreateTestStructure(t *testing.T, baseDir string, files map[string]string) {
	for path, content := range files {
		fullPath := filepath.Join(baseDir, path)

		// Create directory if it doesn't exist
		dir := filepath.Dir(fullPath)
		err := os.MkdirAll(dir, 0755)
		require.NoError(t, err, "Failed to create directory: %s", dir)

		// Write file
		err = ioutil.WriteFile(fullPath, []byte(content), 0644)
		require.NoError(t, err, "Failed to write file: %s", fullPath)
	}
}

// CreateSampleWebProject creates a sample web project structure for testing
func CreateSampleWebProject(t *testing.T, baseDir string) {
	files := map[string]string{
		"index.html": `<!DOCTYPE html>
<html>
<head>
    <title>Test Website</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <h1>Test Website</h1>
    <div id="root"></div>
    <script src="js/bundle.js"></script>
</body>
</html>`,
		"css/style.css": `body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 20px;
}
h1 {
    color: #2c3e50;
}`,
		"js/bundle.js":     GetWebpackScript(),
		"js/bundle.min.js": GetMinifiedScript(),
		"package.json": `{
  "name": "test-website",
  "version": "1.0.0",
  "dependencies": {
    "react": "^17.0.2",
    "react-dom": "^17.0.2",
    "axios": "^0.21.1"
  }
}`,
	}

	CreateTestStructure(t, baseDir, files)
}

// CreateSampleVulnerableProject creates a sample project with vulnerabilities for testing
func CreateSampleVulnerableProject(t *testing.T, baseDir string) {
	files := map[string]string{
		"index.html": `<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Website</title>
    <link rel="stylesheet" href="css/style.css">
</head>
<body>
    <h1>Vulnerable Website</h1>
    <div id="output"></div>
    <form id="userForm">
        <input type="text" id="userInput" name="userInput">
        <button type="submit">Submit</button>
    </form>
    <script src="js/vulnerable.js"></script>
</body>
</html>`,
		"js/vulnerable.js": GetVulnerableScript(),
		"js/config.js": `const config = {
    apiKey: "AIzaSyDz3vSMCvWsv4vKdyJY8-f1MWpHw6Z0VOA",
    databaseURL: "https://example-app.firebaseio.com",
    authDomain: "example-app.firebaseapp.com",
    password: "super_secret_password123"
};`,
	}

	CreateTestStructure(t, baseDir, files)
}

// CleanupTempFiles removes temporary files and directories
func CleanupTempFiles(paths ...string) {
	for _, path := range paths {
		os.RemoveAll(path)
	}
}

// SetupTestLogger creates a logger for testing
func SetupTestLogger(t *testing.T) *logger.Logger {
	return logger.NewLogger()
}

// SetupTestConfig creates a test configuration
func SetupTestConfig() *config.Config {
	return config.LoadDefaultConfig()
}

// CreateTempJSFile creates a temporary JavaScript file with the given content
func CreateTempJSFile(t *testing.T, content string) string {
	// Create temporary directory
	tempDir, err := ioutil.TempDir("", "spiderjs-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Create file path
	filePath := filepath.Join(tempDir, "test.js")

	// Write content to file
	err = ioutil.WriteFile(filePath, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}

	// Add cleanup
	t.Cleanup(func() {
		os.RemoveAll(tempDir)
	})

	return filePath
}

// GetTestDataFilePath returns the path to a test data file
func GetTestDataFilePath(t *testing.T, filename string) string {
	// Get project root directory
	projectRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current directory: %v", err)
	}

	// Navigate to test data directory
	for {
		if _, err := os.Stat(filepath.Join(projectRoot, "tests", "testdata")); err == nil {
			break
		}
		parent := filepath.Dir(projectRoot)
		if parent == projectRoot {
			t.Fatalf("Failed to find tests/testdata directory")
		}
		projectRoot = parent
	}

	// Return path to test data file
	return filepath.Join(projectRoot, "tests", "testdata", filename)
}

// Constants
const (
	DefaultTestTimeout = 30 * 1000 * 1000 * 1000 // 30 seconds in nanoseconds
)

// Sample JavaScript scripts
const (
	// Sample webpack script
	WebpackScript = `
		(function(modules) {
			var installedModules = {};
			function __webpack_require__(moduleId) {
				// webpack module loading logic
			}
			__webpack_require__.m = modules;
			__webpack_require__.c = installedModules;
			__webpack_require__.d = function(exports, name, getter) {};
			__webpack_require__.r = function(exports) {};
			return __webpack_require__(__webpack_require__.s = 0);
		})({
			0: function(module, exports, __webpack_require__) {
				module.exports = __webpack_require__(1);
			},
			1: function(module, exports) {
				console.log("Hello from webpack!");
			}
		});
	`

	// Sample rollup script
	RollupScript = `
		(function (global, factory) {
			typeof exports === 'object' && typeof module !== 'undefined' ? factory(exports) :
			typeof define === 'function' && define.amd ? define(['exports'], factory) :
			(global = global || self, factory(global.myBundle = {}));
		}(this, (function (exports) { 'use strict';
			var foo = 'bar';
			exports.foo = foo;
			Object.defineProperty(exports, '__esModule', { value: true });
			console.log('ROLLUP_CHUNK_ID');
		})));
	`

	// Sample minified script
	MinifiedScript = `var a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=10,k=11,l=12,m=13,n=14,o=15,p=16,q=17,r=18,s=19,t=20,u=21,v=22,w=23,x=24,y=25,z=26;function aa(a,b){return a+b}function ab(a,b){return a-b}function ac(a,b){return a*b}function ad(a,b){return a/b}console.log(aa(1,2),ab(3,4),ac(5,6),ad(7,8));`

	// Sample script with dependencies
	DependenciesScript = `
		import React from 'react';
		import { useState } from 'react';
		import PropTypes from 'prop-types';
		import styled from 'styled-components';
		import { connect } from 'react-redux';
		import axios from 'axios';
		const lodash = require('lodash');
		require('moment');
	`

	// Sample script with vulnerabilities
	VulnerableScript = `
		function processInput(input) {
			eval(input); // Dangerous eval
			document.write(input); // XSS vulnerability
			document.getElementById('result').innerHTML = input; // XSS vulnerability
			setTimeout(input, 1000); // Potential code injection
			new Function(input)(); // Code injection
		}
	`
)
