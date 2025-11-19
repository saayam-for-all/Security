const express = require('express');
const mysql = require('mysql');
const app = express();

// SQL Injection vulnerability - CodeQL will catch this!
app.get('/user', (req, res) => {
  const userId = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + userId;
  connection.query(query, (error, results) => {
    res.json(results);
  });
});

// Command Injection vulnerability
app.get('/ping', (req, res) => {
  const host = req.query.host;
  const exec = require('child_process').exec;
  exec('ping -c 4 ' + host, (error, stdout) => {
    res.send(stdout);
  });
});

// XSS vulnerability
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  res.send('<html><body>You searched for: ' + searchTerm + '</body></html>');
});

// Hardcoded secret - will also trigger secret scanning
const API_KEY = "sk_live_51H8xYzAbCdEfGhIjKlMnOpQrStUvWxYz";

app.listen(3000);
