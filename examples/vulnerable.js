// Vulnerable JavaScript example for SpiderJS scanner
const express = require('express');
const app = express();

// Vulnerable route with SQL injection
app.get('/users', (req, res) => {
  const userId = req.query.id;
  // Vulnerable SQL query
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  
  // Simulate database response
  res.json({
    query: query,
    user: { id: userId, name: 'Test User' }
  });
});

// Vulnerable route with XSS
app.get('/profile', (req, res) => {
  const name = req.query.name;
  // No sanitization
  res.send(`
    <html>
      <head><title>User Profile</title></head>
      <body>
        <h1>Welcome, ${name}!</h1>
      </body>
    </html>
  `);
});

// Prototype pollution
function merge(target, source) {
  for (let key in source) {
    if (source.hasOwnProperty(key)) {
      if (typeof source[key] === 'object') {
        target[key] = merge(target[key] || {}, source[key]);
      } else {
        target[key] = source[key];
      }
    }
  }
  return target;
}

app.post('/merge', express.json(), (req, res) => {
  const result = {};
  merge(result, req.body);
  res.json(result);
});

app.listen(3000, () => {
  console.log('Vulnerable app listening on port 3000');
}); 