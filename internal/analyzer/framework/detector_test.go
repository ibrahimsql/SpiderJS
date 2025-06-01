package framework

import (
	"context"
	"testing"

	"github.com/ibrahimsql/spiderjs/internal/utils/logger"
	"github.com/ibrahimsql/spiderjs/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDetector(t *testing.T) {
	// Setup logger
	log := logger.NewLogger()

	// Test with valid logger
	detector, err := NewDetector(log)
	assert.NoError(t, err)
	assert.NotNil(t, detector)

	// Test with nil logger
	detector, err = NewDetector(nil)
	assert.Error(t, err)
	assert.Nil(t, detector)
}

func TestDetect(t *testing.T) {
	// Setup logger
	log := logger.NewLogger()

	// Setup detector
	detector, err := NewDetector(log)
	require.NoError(t, err)

	// Test with nil target
	frameworks, err := detector.Detect(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, frameworks)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	frameworks, err = detector.Detect(ctx, &models.Target{})
	assert.Error(t, err)
	assert.Nil(t, frameworks)

	// Test with empty target
	target, err := models.NewTarget("https://example.com")
	require.NoError(t, err)
	frameworks, err = detector.Detect(context.Background(), target)
	assert.NoError(t, err)
	assert.Empty(t, frameworks)

	// Test with React script
	target.Scripts = append(target.Scripts, `
		import React from 'react';
		import ReactDOM from 'react-dom';
		
		function App() {
			const [count, setCount] = React.useState(0);
			
			React.useEffect(() => {
				document.title = 'Count: ' + count;
			}, [count]);
			
			return React.createElement('div', null, 'Hello React!');
		}
		
		ReactDOM.render(
			React.createElement(App, null),
			document.getElementById('root')
		);
	`)
	frameworks, err = detector.Detect(context.Background(), target)
	assert.NoError(t, err)
	assert.NotEmpty(t, frameworks)
	for _, framework := range frameworks {
		if framework.Type == React {
			assert.Equal(t, React, framework.Type)
			assert.True(t, framework.Score > 0)
			break
		}
	}

	// Test with Vue script
	target.Scripts = []string{`
		import Vue from 'vue';
		
		new Vue({
			el: '#app',
			data: {
				message: 'Hello Vue!'
			},
			computed: {
				reversedMessage() {
					return this.message.split('').reverse().join('');
				}
			},
			watch: {
				message(newVal, oldVal) {
					console.log('Message changed from', oldVal, 'to', newVal);
				}
			}
		});
	`}
	frameworks, err = detector.Detect(context.Background(), target)
	assert.NoError(t, err)
	assert.NotEmpty(t, frameworks)
	for _, framework := range frameworks {
		if framework.Type == Vue {
			assert.Equal(t, Vue, framework.Type)
			assert.True(t, framework.Score > 0)
			break
		}
	}

	// Test with Angular script
	target.Scripts = []string{`
		import { Component } from '@angular/core';
		
		@Component({
			selector: 'app-root',
			template: '<h1>Hello Angular!</h1>'
		})
		export class AppComponent {
			title = 'My Angular App';
		}
		
		import { NgModule } from '@angular/core';
		import { BrowserModule } from '@angular/platform-browser';
		
		@NgModule({
			declarations: [AppComponent],
			imports: [BrowserModule],
			bootstrap: [AppComponent]
		})
		export class AppModule { }
	`}
	frameworks, err = detector.Detect(context.Background(), target)
	assert.NoError(t, err)
	assert.NotEmpty(t, frameworks)
	for _, framework := range frameworks {
		if framework.Type == Angular {
			assert.Equal(t, Angular, framework.Type)
			assert.True(t, framework.Score > 0)
			break
		}
	}
}

func TestDetectFromTarget(t *testing.T) {
	// Setup logger
	log := logger.NewLogger()

	// Setup detector
	detector, err := NewDetector(log)
	require.NoError(t, err)

	// Test with nil target
	frameworks, err := detector.DetectFromTarget(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, frameworks)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	frameworks, err = detector.DetectFromTarget(ctx, &models.Target{})
	assert.Error(t, err)
	assert.Nil(t, frameworks)

	// Test with empty target
	target, err := models.NewTarget("https://example.com")
	require.NoError(t, err)
	frameworks, err = detector.DetectFromTarget(context.Background(), target)
	assert.NoError(t, err)
	assert.Empty(t, frameworks)

	// Test with headers
	target.Headers["X-Powered-By"] = "Next.js"
	frameworks, err = detector.DetectFromTarget(context.Background(), target)
	assert.NoError(t, err)
	assert.NotEmpty(t, frameworks)
	for _, framework := range frameworks {
		if framework.Type == NextJS {
			assert.Equal(t, NextJS, framework.Type)
			assert.True(t, framework.Score > 0)
			break
		}
	}
}

func TestDetectVersion(t *testing.T) {
	// Setup logger
	log := logger.NewLogger()

	// Setup detector
	detector, err := NewDetector(log)
	require.NoError(t, err)

	// Setup target
	target, err := models.NewTarget("https://example.com")
	require.NoError(t, err)

	// Test React version detection
	target.Scripts = []string{`
		React.version = '17.0.2';
		console.log('React version:', React.version);
	`}
	version := detector.detectVersion(React, target)
	assert.Equal(t, "17.0.2", version)

	// Test Vue version detection
	target.Scripts = []string{`
		Vue.version = '3.2.47';
		console.log('Vue version:', Vue.version);
	`}
	version = detector.detectVersion(Vue, target)
	assert.Equal(t, "3.2.47", version)

	// Test Angular version detection
	target.Scripts = []string{`
		VERSION.full = '15.1.0';
		console.log('Angular version:', VERSION.full);
	`}
	version = detector.detectVersion(Angular, target)
	assert.Equal(t, "15.1.0", version)

	// Test unknown version
	target.Scripts = []string{`
		console.log('Hello World!');
	`}
	version = detector.detectVersion(React, target)
	assert.Equal(t, "", version)
}

func TestIsMetaFramework(t *testing.T) {
	// Setup logger
	log := logger.NewLogger()

	// Setup detector
	detector, err := NewDetector(log)
	require.NoError(t, err)

	// Test meta frameworks
	assert.True(t, detector.isMetaFramework(NextJS))
	assert.True(t, detector.isMetaFramework(NuxtJS))
	assert.True(t, detector.isMetaFramework(Gatsby))
	assert.True(t, detector.isMetaFramework(Remix))

	// Test non-meta frameworks
	assert.False(t, detector.isMetaFramework(React))
	assert.False(t, detector.isMetaFramework(Vue))
	assert.False(t, detector.isMetaFramework(Angular))
	assert.False(t, detector.isMetaFramework(Svelte))
}

func TestDetectError(t *testing.T) {
	// Setup logger
	log := logger.NewLogger()

	// Setup detector
	detector, err := NewDetector(log)
	require.NoError(t, err)

	// Test with nil target
	frameworks, err := detector.Detect(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, frameworks)

	// Test with empty target
	target := &models.Target{}
	frameworks, err = detector.Detect(context.Background(), target)
	assert.NoError(t, err)
	assert.Empty(t, frameworks)
}
