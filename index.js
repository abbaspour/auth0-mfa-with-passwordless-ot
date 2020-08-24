'use strict';

require('dotenv').config();
const app = require('./app');
const http = require('http');

const port = process.env.port || 3000;

console.log(`starting server on port ${port} for request from domain: ${process.env.AUTH0_DOMAIN}`);

http.createServer(app).listen(port);

console.log(`server is up as client: ${process.env.CLIENT_ID}`);

