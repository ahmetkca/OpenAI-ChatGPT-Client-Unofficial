
import { ClientRequest, IncomingMessage, OutgoingHttpHeaders } from 'node:http';
import * as https from 'node:https';
const randUserAgent = require('rand-user-agent');

import { randomUUID } from 'node:crypto';


type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';

const useraAgent = randUserAgent("desktop");

interface Builder<T, Z> {
  setHostname(hostname: string): T;
  setPort(port: number): T;
  setPath(path: string): T;
  setMethod(method: HttpMethod): T;
  setHeaders(headers: OutgoingHttpHeaders): T;
  setAgent(agent: https.Agent): T;
  build(): Z;
};

class HttpBuilder implements Builder<HttpBuilder, HttpClient> {
  private httpClient: HttpClient;

  constructor(httpClient?: HttpClient) {
    this.httpClient = httpClient || new HttpClient();
  }  
  setHostname(hostname: string): HttpBuilder {
    this.httpClient._reqOptions.hostname = hostname;
    return this;
  }
  setPort(port: number): HttpBuilder {
    this.httpClient._reqOptions.port = port;
    return this;
  }
  setPath(path: string): HttpBuilder {
    this.httpClient._reqOptions.path = path;
    return this;
  }
  setMethod(method: HttpMethod): HttpBuilder {
    this.httpClient._reqOptions.method = method;
    return this;
  }
  setHeaders(headers: OutgoingHttpHeaders): HttpBuilder {
    this.httpClient._reqOptions.headers = headers;
    return this;
  }
  setAgent(agent: https.Agent): HttpBuilder {
    this.httpClient._reqOptions.agent = agent;
    return this;
  }
  build(): HttpClient {
    return this.httpClient;
  }
  
}

class HttpClient {
  private readonly _httpsAgent: https.Agent;
  public readonly _reqOptions: https.RequestOptions;
 
  constructor() {
    this._httpsAgent = new https.Agent({
      rejectUnauthorized: false,
      keepAlive: true,
    });
    this._reqOptions = {};
  }

  public request(options: https.RequestOptions, payload?: string, encoding: BufferEncoding = 'utf-8'): Promise<[IncomingMessage, string]> {
    return new Promise((resolve, reject) => {
        console.log('fetching', options);
        const req = https.request({
            ...options,
        }, (res) => {
            let data: string = "";
            res.setEncoding(encoding);
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                resolve([res, data]);
            });
        })
            .on('error', (err) => {
                reject(err);
            });
        if (options.method &&
            ['POST', 'PUT'].includes(options.method) &&
            payload) {
            req.write(payload);
        }
        req.end();
    });
  }

  public readonly getHeaders = (): OutgoingHttpHeaders | undefined => {
    return this._reqOptions?.headers;
  }

  public readonly getRequestOptions = (): https.RequestOptions => {
    return this._reqOptions;
  }
}

interface AuthSessionReturnData {
  user: {
    id: string;
    name: string;
    email: string;
    image: string;
    picture: string;
    groups: string[];
    features: string[];
  };
  expires: Date;
  accessToken: string;
}

class ChatGPTAuth {
  private _email: string;
  private _password: string;
  private _cookies: string[] = [];
  private _authSessionJsonData: AuthSessionReturnData | undefined;
  private readonly _httpAgent: https.Agent;
  private readonly _httpClient: HttpClient;
  constructor(email: string, password: string) {
    this._email = email;
    this._password = password;
    this._httpAgent = new https.Agent({
      keepAlive: true,
      maxSockets: 1,
      maxFreeSockets: 1,
    });
    this._httpClient = new HttpBuilder()
      .setHostname('chat.openai.com')
      .setPort(443)
      .setPath('/auth/login')
      .setMethod('GET')
      .setHeaders({
        "User-Agent": useraAgent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
      })
      .setAgent(this._httpAgent)
      .build();
  }


  async login() {
    console.log('Logging in...');

    await delay(randomMilliseconds(500, 1000));
    const [res, data] = await this._httpClient.request(this._httpClient.getRequestOptions());

    const cookies = res.headers['set-cookie'] ?? [];

    if (res.statusCode !== 200) {
      throw new Error(`Login failed with status code ${res.statusCode}`);
    }
    
    console.log(`cookies: ${cookies}`);

    const [resCsrf, dataCsrf] = await this._httpClient.request({
      ...this._httpClient.getRequestOptions(),
      path: '/api/auth/csrf',
      method: 'GET',
      headers: {
        ...this._httpClient.getHeaders(),

  }

  // async getCsrfToken(cookies?: string[]) {
  //   const headers: OutgoingHttpHeaders = {
  //     "Accept": "*/*",
  //     "Accept-Encoding": "gzip, deflate, br",
  //     "Accept-Language": "en-US,en;q=0.9",
  //     "Connection": "keep-alive",
  //     "referer": "https://chat.openai.com/auth/login",
  //     "User-Agent": useraAgent,
  //     "sec-ch-ua-platform": "Windows",
  //     "sec-fetch-dest": "empty",
  //     "sec-fetch-mode": "cors",
  //     "sec-fetch-site": "same-origin",
  //   };
  //   if (cookies) {
  //     headers['Cookie'] = cookies;
  //   }
  //   await delay(randomMilliseconds(500, 1000));
  //   await (new HttpBuilder(this._httpClient)
  //     .setPath("/api/auth/csrf")
  //     .setHeaders(headers)
  //     .build())
  //   .request(async (req, res) => {
      
      

  //     console.log(`STATUS: ${res.statusCode}`);
  //     console.log(`RESPONSE HEADERS: ${JSON.stringify(res.headers)}`);

  //     console.log(`REQUEST HEADERS: ${JSON.stringify(req.getHeaders())}`);

  //     let nextCookies = res.headers['set-cookie'] ?? [];
  //     nextCookies = nextCookies.concat(cookies ?? []);


  //     if (res.statusCode === 200 && res.statusMessage === 'OK') {
  //       console.log('Auth second flow step success CSRF Token');
  //     } else {
  //       console.error('Auth second flow step failed CSRF Token');
  //       return;
  //     }
      
  //     let data = '';
  //     console.log(`${JSON.stringify(res.headers)}`);

  //     res.setEncoding('utf8');

  //     res.on('data', (chunk) => {
  //       console.log("CSRF Token");
  //       console.log(`BODY: ${chunk}`);
  //       data += chunk;
  //     });

  //     res.on('end', async () => {
  //       console.log('No more data in response.');
  //       if (res.statusCode === 200 && res.statusMessage === "OK") {
  //         await this.getAuthUrl(JSON.parse(data).csrfToken, nextCookies);
  //       } else {
  //         console.error("CSRF Token auth flow failed!");
  //         throw new Error("CSRF Token auth flow failed!");
  //       }
  //     });
  //   });
  // }

  // async getAuthUrl(csrfToken: string, cookies?: string[]) {
  //   const headers: OutgoingHttpHeaders = {
  //     "Content-Type": "application/x-www-form-urlencoded",
  //     "Accept": "*/*",
  //     "Accept-Encoding": "gzip, deflate, br",
  //     "Accept-Language": "en-US,en;q=0.9",
  //     "Connection": "keep-alive",
  //     "referer": "https://chat.openai.com/auth/login",
  //     "User-Agent": useraAgent,
  //     "Origin": "https://chat.openai.com",
  //     "Authority": "chat.openai.com",
  //     "sec-ch-ua-platform": "Windows",
  //     "sec-fetch-dest": "empty",
  //     "sec-fetch-mode": "cors",
  //     "sec-fetch-site": "same-origin",
  //   };
  //   if (cookies) {
  //     headers['Cookie'] = cookies;
  //   }

  //   const formData: Map<string, string> = new Map();
  //   formData.set("callbackUrl", "/");
  //   formData.set("csrfToken", csrfToken);
  //   formData.set("json", "true");

      
  //   const urlencodedFormData = encodeFormData(formData);

  //   await delay(randomMilliseconds(500, 1000));
  //   await (new HttpBuilder(this._httpClient)
  //     .setPath("/api/auth/signin/auth0?prompt=login")
  //     .setMethod("POST")
  //     .setHeaders( headers)
  //     .build())
  //   .request(async (req, res) => {
  //     let data = '';

  //     console.log(`statusCode: ${res.statusCode}`);
  //     console.log(`statusMessage: ${res.statusMessage}`);
  //     console.log(`${JSON.stringify(res.headers)}`);
  //     console.log(`${JSON.stringify(req.getHeaders())}`);

  //     let nextCookies = res.headers['set-cookie'] ?? [];
  //     nextCookies = nextCookies.concat(cookies ?? []);

  //     res.setEncoding('utf8');

  //     res.on('data', (chunk) => {
  //       console.log("Auth URL");
  //       console.log(`BODY: ${chunk}`);
  //       data += chunk;
  //     });

  //     res.on('end', async () => {
  //       console.log('No more data in response.');
  //       console.log(`BODY: ${data}`);
  //       const jsonData = JSON.parse(data);
  //       if (res.statusCode === 200 && res.statusMessage === "OK") {
  //         console.log("Auth URL success");
  //         await this.authorizeByAuthUrl(new URL(jsonData.url), nextCookies);
  //       } else {
  //         console.error("Auth URL failed");
  //         throw new Error("Auth URL failed");
  //       }
  //     });

  //   }, urlencodedFormData);
  // }

  // async authorizeByAuthUrl(authUrl: URL, cookies?: string[]) {
  //   const headers: OutgoingHttpHeaders = {
  //     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  //     "Accept-Encoding": "gzip, deflate, br",
  //     "Accept-Language": "en-CA,en-US;q=0.7,en;q=0.3",
  //     "Connection": "keep-alive",
  //     "referer": "https://chat.openai.com/",
  //     "User-Agent": useraAgent,
  //     "upgrade-insecure-requests": 1,
  //     "sec-fetch-dest": "document",
  //     "sec-fetch-mode": "navigate",
  //     "sec-fetch-site": "same-site",
  //     "sec-fetch-user": "?1",
  //     "sec-gpc": 1,
  //     "te": "trailers",
  //     "content-length": 0,
  //   };
  //   if (cookies) {
  //     headers['Cookie'] = cookies;
  //   }
  //   await delay(randomMilliseconds(500, 2500));
  //   await (new HttpBuilder(this._httpClient)
  //     .setHostname(authUrl.hostname)              // TODO extract hostname from `authUrl`
  //     .setPath(authUrl.pathname + authUrl.search) // TODO extract path from `authUrl` with query params
  //     .setHeaders(headers)
  //     .setMethod("GET")
  //     .build())
  //   .request(async (req, res) => {
  //     let data = '';

  //     console.log(`statusCode: ${res.statusCode}`);
  //     console.log(`statusMessage: ${res.statusMessage}`);
  //     console.log(`${JSON.stringify(res.headers)}`);
  //     console.log(`${JSON.stringify(req.getHeaders())}`);

  //     let nextCookies = res.headers['set-cookie'] ?? [];
  //     nextCookies = nextCookies.concat(cookies ?? []);

  //     res.setEncoding('utf8');

  //     res.on('data', (chunk) => {
  //       data += chunk;
  //     });

  //     res.on('end', async () => {
  //       console.log('No more data in response.');
  //       console.log(`BODY: ${data}`);
  //       console.log(`Location: ${res.headers['location']}`);
  //       if (res.headers['location'] === undefined) {
  //         throw new Error("Location header not found (/u/login/indentifier=?state=)");
  //       }

  //       if (res.statusCode === 302 && 
  //           res.statusMessage === "Found" && 
  //           res.headers['location'].startsWith("/u/login/identifier?state=")) {
  //         console.log("AUTHORIZE Auth URL success");
  //         await this.preLoginIdentifier(new URL("https://auth0.openai.com" + res.headers['location']), nextCookies);
  //       } else {
  //         console.error("AUTHORIZE Auth URL failed");
  //         throw new Error("AUTHORIZE Auth URL failed");
  //       }
  //     });
  //   });
  // }

  // async preLoginIdentifier(url: URL, cookies?: string[]) {
  //   console.log(url);
  //   console.log(cookies);

  //   // return;
  //   const headers: OutgoingHttpHeaders = {
  //     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  //     "Accept-Encoding": "gzip, deflate, br",
  //     "Accept-Language": "en-CA,en-US;q=0.7,en;q=0.3",
  //     "Connection": "keep-alive",
  //     "referer": "https://chat.openai.com/",
  //     "User-Agent": useraAgent,
  //     "upgrade-insecure-requests": 1,
  //     "sec-fetch-dest": "document",
  //     "sec-fetch-mode": "navigate",
  //     "sec-fetch-site": "same-site",
  //     "sec-fetch-user": "?1",
  //     "sec-gpc": 1,
  //     "te": "trailers",
  //     "content-length": 0,
  //   };
  //   if (cookies) {
  //     headers['Cookie'] = cookies;
  //   }
  //   await delay(randomMilliseconds(2000, 3000));
  //   await (new HttpBuilder(this._httpClient)
  //     .setHostname(url.hostname)
  //     .setPath(url.pathname + url.search)
  //     .setHeaders(headers)
  //     .setMethod("GET")
  //     .build())
  //   .request(async (req, res) => {
      
  //     let data = '';

  //     console.log(`statusCode: ${res.statusCode}`);
  //     console.log(`statusMessage: ${res.statusMessage}`);
  //     console.log(`${JSON.stringify(res.headers)}`);
  //     console.log(`${JSON.stringify(req.getHeaders())}`);

  //     let nextCookies = res.headers['set-cookie'] ?? [];
  //     nextCookies = nextCookies.concat(cookies ?? []);

  //     console.log(nextCookies);

  //     res.setEncoding('utf8');

  //     res.on('data', (chunk) => {
  //       data += chunk;
  //     });

  //     res.on('end', async () => {
  //       console.log("preLoginIdentifier");
  //       console.log('No more data in response.');
  //       console.log(`BODY: ${data}`);
  //       console.log(res.headers['location']);
  //       console.log(res.headers['set-cookie']);
  //       console.log(`statusCode: ${res.statusCode}`);
  //       console.log(`statusMessage: ${res.statusMessage}`);
  //       await this.loginIdentifierByEmail(url, nextCookies);
  //     });
    
  //   });
  // }

  // async loginIdentifierByEmail(url: URL, cookies?: string[]) {

  //   if (!this._email) {
  //     throw new Error("Email is not set");
  //   }

  //   if (url.searchParams.get("state") === null) {
  //     throw new Error("auth flow state is not set");
  //   }

  //   const formData: Map<string, string> = new Map();
  //   formData.set("state", url.searchParams.get("state")!);
  //   formData.set("username", this._email);
  //   formData.set("js-available", "true");
  //   formData.set("webauthn-available", "true");
  //   formData.set("is-brave", "false");
  //   formData.set("webauthn-platform-available", "true");
  //   formData.set("action", "default");
  //   const encodedFormData = encodeFormData(formData);

  //   console.log(encodedFormData);

  //   const headers: OutgoingHttpHeaders = {
  //     "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  //     "accept-language": "en-CA,en-US;q=0.7,en;q=0.3",
  //     "accept-encoding": "gzip, deflate, br",
  //     "referer": url.toString(),
  //     "content-type": "application/x-www-form-urlencoded",
  //     "content-length": encodedFormData.length,
  //     "User-Agent": useraAgent,
  //     "origin": "https://auth0.openai.com",
  //     "upgrade-insecure-requests": 1,
  //     "Connection": "keep-alive",
  //     "sec-fetch-dest": "document",
  //     "sec-fetch-mode": "navigate",
  //     "sec-fetch-site": "same-origin",
  //     "sec-fetch-user": "?1",
  //     "sec-gpc": 1,
  //     "te": "trailers",
  //   }

  //   if (cookies) {
  //     headers['Cookie'] = cookies;
  //     console.log("cookies: " + cookies);
  //   } else {
  //     throw new Error("cookies are not set");
  //   }
  //   await delay(randomMilliseconds(2500, 3500));
  //   await (new HttpBuilder(this._httpClient)
  //     .setHostname(url.hostname)
  //     .setPath(url.pathname + url.search)
  //     .setHeaders(headers)
  //     .setMethod("POST")
  //     .build())
  //   .request(async (req, res) => {

  //     let data = '';

  //     console.log(`statusCode: ${res.statusCode}`);
  //     console.log(`statusMessage: ${res.statusMessage}`);
  //     console.log(`${JSON.stringify(res.headers)}`);
  //     console.log(`${JSON.stringify(req.getHeaders())}`);

  //     let nextCookies = res.headers['set-cookie'] ?? [];
  //     nextCookies = nextCookies.concat(cookies ?? []);

  //     res.setEncoding('utf8');

  //     res.on('data', (chunk) => {
  //       data += chunk;
  //     });

  //     res.on('end', async () => {
  
  //       console.log(`BODY: ${data}`);
  //       console.log("loginIdentifierByEmail");
  //       console.log('No more data in response.');
  //       console.log(`statusCode: ${res.statusCode}`);
  //       console.log(`statusMessage: ${res.statusMessage}`);

  //       console.log(`Location from response headers: ${res.headers.location}`);
  //       console.log(`statusCode: ${res.statusCode}`);
  //       console.log(`statusMessage: ${res.statusMessage}`);
  //       const regex: RegExp = /<a href="([a-zA-Z0-9@.-_\/?=&]+)">/gm;
  //       const match = regex.exec(data);
  //       if (match === null) {
  //         console.error("Could not find login password url");
  //       } else {
  //         console.log(`Location from RegexExp: ${match[1]}`);
  //         await this.preLoginPassword(url.toString(), new URL("https://" + url.hostname + res.headers.location), nextCookies);
  //       }        
  //     });

  //   }, encodedFormData);
  // }

  // async preLoginPassword(refererUrlForHeaders: string, logingPasswordUrl: URL, cookies?: string[]) {
  //   const headers: OutgoingHttpHeaders = {
  //     "User-Agent": useraAgent,
  //     "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  //     "accept-language": "en-CA,en-US;q=0.7,en;q=0.3",
  //     "accept-encoding": "gzip, deflate, br",
  //     "referer": refererUrlForHeaders,
  //     "upgrade-insecure-requests": 1,
  //     "Connection": "keep-alive",
  //     "sec-fetch-dest": "document",
  //     "sec-fetch-mode": "navigate",
  //     "sec-fetch-site": "same-origin",
  //     "sec-fetch-user": "?1",
  //     "sec-gpc": 1,
  //     "te": "trailers",
  //     "content-length": 0,
  //   }

  //   if (cookies) {
  //     headers['Cookie'] = cookies;
  //     // console.log("cookies: " + cookies);
  //   } else {
  //     throw new Error("cookies are not set");
  //   }
  //   await delay(randomMilliseconds(500, 1000));
  //   await (new HttpBuilder(this._httpClient)
  //     .setHostname(logingPasswordUrl.hostname)
  //     .setPath(logingPasswordUrl.pathname + logingPasswordUrl.search)
  //     .setHeaders(headers)
  //     .setMethod("GET")
  //     .build())
  //   .request(async (req, res) => {

  //       let data = '';

  //       console.log(`statusCode: ${res.statusCode}`);
  //       console.log(`statusMessage: ${res.statusMessage}`);
  //       console.log(`${JSON.stringify(res.headers)}`);
  //       console.log(`${JSON.stringify(req.getHeaders())}`);

  //       let nextCookies = res.headers['set-cookie'] ?? [];
  //       nextCookies = nextCookies.concat(cookies ?? []);

  //       res.setEncoding('utf8');

  //       res.on('data', (chunk) => {
  //         data += chunk;
  //       });

  //       res.on('end', async () => {
  //         console.log("preLoginPassword");
  //         console.log('No more data in response.');
  //         console.log(`BODY: ${data}`);
  //         const regex: RegExp = /<span class="ulp-authenticator-selector-text">([a-zA-Z0-9@.-_]+)<\/span>/gm;
  //         const match = regex.exec(data);
  //         if (match === null) {
  //           console.error("Could not find login password url");
  //         } else {
  //           console.log(`refererUrlForHeaders: ${refererUrlForHeaders}`);
  //           console.log(`logingPasswordUrl: ${logingPasswordUrl.toString()}`);
  //           console.log(`cookies: ${cookies}`);
  //           console.log(`nextCookies: ${nextCookies}`);
  //           console.log(`Login password url: ${match[1]}`);
  //           if (match[1] !== this._email) {
  //             console.error("Email does not match");
  //             throw new Error("Email does not match");
  //           }
            
  //           console.log("Email matches");
  //           await this.loginPassword(logingPasswordUrl, nextCookies);

  //         }
  //       });
  //     });
  // }

  // async loginPassword(loginPasswordUrl: URL, cookies: string[]) {
  //   if (this._password === undefined) {
  //     throw new Error("Password is not set");
  //   }

  //   if (loginPasswordUrl.searchParams.get("state") === null) {
  //     throw new Error("state is not set");
  //   }

    //  const formData: Map<string, string> = new Map();
  //   formData.set("state", loginPasswordUrl.searchParams.get("state")!);
  //   formData.set("username", this._email);
  //   formData.set("password", this._password);
  //   formData.set("action", "default");

  //   const encodedFormData = encodeFormData(formData);

  //   const headers: OutgoingHttpHeaders = {
  //     "user-agent": useraAgent,
  //     "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  //     "accept-language": "en-CA,en-US;q=0.7,en;q=0.3",
  //     "accept-encoding": "gzip, deflate, br",
  //     "referer": loginPasswordUrl.toString(),
  //     "content-type": "application/x-www-form-urlencoded",
  //     "Connection": "keep-alive",
  //     "content-length": encodedFormData.length,
  //     "origin": "https://auth0.openai.com",
  //     "upgrade-insecure-requests": 1,
  //     "sec-fetch-dest": "document",
  //     "sec-fetch-mode": "navigate",
  //     "sec-fetch-site": "same-origin",
  //     "sec-fetch-user": "?1",
  //     "sec-gpc": 1,
  //     "te": "trailers",
  //   }

  //   if (cookies) {
  //     headers['Cookie'] = cookies;
  //   }

  //   await delay(randomMilliseconds(1250, 3350));
  //   await (new HttpBuilder(this._httpClient)
  //     .setHostname(loginPasswordUrl.hostname)
  //     .setPath(loginPasswordUrl.pathname + loginPasswordUrl.search)
  //     .setHeaders(headers)
  //     .setMethod("POST")
  //     .build())
  //   .request(async (req, res) => {
  //     let data = '';

  //     let nextCookies = res.headers['set-cookie'] ?? [];
  //     nextCookies = nextCookies.concat(cookies ?? []);

  //     res.setEncoding('utf8');

  //     res.on('data', (chunk) => {
  //       data += chunk;
  //     });

  //     res.on('end', async () => {
  //       console.log("loginPassword");
  //       console.log('No more data in response.');
  //       console.log(`BODY: ${data}`);
  //       console.log(`statusCode: ${res.statusCode}`);
  //       console.log(`statusMessage: ${res.statusMessage}`);
  //       console.log(`${JSON.stringify(res.headers)}`);
  //       console.log(`${JSON.stringify(req.getHeaders())}`);
  //       console.log(`nextCookies: ${nextCookies}`);
  //       if (res.statusCode === 400 && res.statusMessage === "Bad Request") {
  //         const regex: RegExp = /Wrong email or password/gm;
  //         const match = regex.exec(data);
  //         if (match === null) {
  //           throw new Error("Could not find error message. Probably wrong email or password");
  //         }
  //         console.error("Wrong email or password");
  //         throw new Error("Wrong email or password");
  //       }

  //       if (res.headers.location === undefined) {
  //         throw new Error("Redirect location is not set");
  //       }

  //       const redirectUrl = new URL("https://" + loginPasswordUrl.hostname + res.headers.location);
  //       console.log(`Redirect url: ${redirectUrl.toString()}`);
  //       await this.authorizeResume(loginPasswordUrl.toString(), redirectUrl, nextCookies);
  //     });
  //   }, encodedFormData);

  // }

  // async authorizeResume(refererUrlForHeaders: string, resumeUrl: URL, cookies: string[]) {
  //   // TODO the response of resumeUrl provides a redirect location callback url (this url is a whole url with https:// etc.)
  //   // can create it with new URL(res.headers.location);

  //   // and then make a call to authCallback with the cookies and the callback url
  //   const headers: OutgoingHttpHeaders = {
  //     "user-agent": useraAgent,
  //     "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  //     "accept-language": "en-CA,en-US;q=0.7,en;q=0.3",
  //     "accept-encoding": "gzip, deflate, br",
  //     "referer": refererUrlForHeaders,
  //     "Connection": "keep-alive",
  //     "upgrade-insecure-requests": 1,
  //     "sec-fetch-dest": "document",
  //     "sec-fetch-mode": "navigate",
  //     "sec-fetch-site": "same-origin",
  //     "sec-fetch-user": "?1",
  //     "sec-gpc": 1,
  //     "te": "trailers",
  //   }

  //   if (cookies) {
  //     headers['Cookie'] = cookies;
  //   }

  //   await delay(randomMilliseconds(1250, 3350));
  //   await (new HttpBuilder(this._httpClient)
  //     .setHostname(resumeUrl.hostname)
  //     .setPath(resumeUrl.pathname + resumeUrl.search)
  //     .setHeaders(headers)
  //     .setMethod("GET")
  //     .build())
  //   .request(async (req, res) => {

  //     let data = "";

  //     let nextCookies = res.headers['set-cookie'] ?? [];
  //     nextCookies = nextCookies.concat(cookies ?? []);

  //     res.setEncoding('utf8');

  //     res.on('data', (chunk) => {
  //       data += chunk;
  //     });

  //     res.on('end', async () => {
  //       console.log("authorizeResume");
  //       console.log('No more data in response.');
  //       console.log(`BODY: ${data}`);
  //       console.log(`statusCode: ${res.statusCode}`);
  //       console.log(`statusMessage: ${res.statusMessage}`);
  //       console.log(`${JSON.stringify(res.headers)}`);
  //       console.log(`${JSON.stringify(req.getHeaders())}`);
  //       console.log(`nextCookies: ${nextCookies}`);
  //       if (res.statusCode === 302 && res.statusMessage === "Found") {
  //         if (res.headers.location === undefined) {
  //           throw new Error("Redirect location is not set");
  //         }
  //         console.log(`Redirect location: ${res.headers.location}`);
  //         const authCallbackUrl = new URL(res.headers.location);
  //         console.log(`Redirect url: ${authCallbackUrl}`);
  //         await this.authCallback(authCallbackUrl, nextCookies);
  //       }
  //     });
  //   });
  // }

  // async authCallback(callbackUrl: URL, cookies: string[]) {
  //   // TODO make a request to callbackUrl with the cookies
  //   // the response of this request contains the session token that can be used to make requests to the api endpoint conversation

  //   // the response of this request also contains a redirect location to the chat url
  //   const headers: OutgoingHttpHeaders = {
  //     "user-agent": useraAgent,
  //     "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
  //     "accept-language": "en-CA,en-US;q=0.7,en;q=0.3",
  //     "accept-encoding": "gzip, deflate, br",
  //     "Connection": "keep-alive",
  //     "upgrade-insecure-requests": 1,
  //     "sec-fetch-dest": "document",
  //     "sec-fetch-mode": "navigate",
  //     "sec-fetch-site": "same-origin",
  //     "sec-fetch-user": "?1",
  //     "sec-gpc": 1,
  //     "te": "trailers", 
  //   }

  //   if (cookies) {
  //     headers['Cookie'] = cookies;
  //   }

  //   await delay(randomMilliseconds(1250, 3350));
  //   await (new HttpBuilder(this._httpClient)
  //     .setHostname(callbackUrl.hostname)
  //     .setPath(callbackUrl.pathname + callbackUrl.search)
  //     .setHeaders(headers)
  //     .setMethod("GET")
  //     .build())
  //   .request(async (req, res) => {
  //     let data = '';

  //     let nextCookies = res.headers['set-cookie'] ?? [];
  //     nextCookies = nextCookies.concat(cookies ?? []);

  //     res.setEncoding('utf8');

  //     res.on('data', (chunk) => {
  //       data += chunk;
  //     });

  //     res.on('end', async () => {
  //       console.log("authCallback");
  //       console.log('No more data in response.');
  //       console.log(`BODY: ${data}`);
  //       console.log(`statusCode: ${res.statusCode}`);
  //       console.log(`statusMessage: ${res.statusMessage}`);
  //       console.log(`${JSON.stringify(res.headers)}`);
  //       console.log(`${JSON.stringify(req.getHeaders())}`);
  //       console.log(`nextCookies: ${nextCookies}`);
  //       if (res.statusCode === 302 && res.statusMessage === "Found") {
  //         if (res.headers.location === undefined) {
  //           throw new Error("Redirect location is not set");
  //         }
  //         console.log(`Redirect location: ${res.headers.location}`);
  //         const chatUrl = new URL(res.headers.location);
  //         console.log(`Redirect url: ${chatUrl}`);
  //         nextCookies.forEach((cookie) => {
  //           console.log(`cookie: ${cookie}`);
  //         });
  //         await this.apiAuthSessionToken(nextCookies);
  //       }
  //     });
  //   });
  // }

  // async apiAuthSessionToken(cookies: string[]) {
  //   const headers: OutgoingHttpHeaders = {
  //     "Host": "chat.openai.com",
  //     "User-Agent": useraAgent,
  //     "Accept": "*/*",
  //     "Accept-Language": "en-CA,en-US;q=0.7,en;q=0.3",
  //     "Accept-Encoding": "gzip, deflate, br",
  //     "Referer": "https://chat.openai.com/chat",
  //     "Connection": "keep-alive",
  //     "Sec-Fetch-Dest": "empty",
  //     "Sec-Fetch-Mode": "cors",
  //     "Sec-Fetch-Site": "same-origin",
  //     "Sec-GPC": 1,
  //     "Pragma": "no-cache",
  //     "Cache-Control": "no-cache",
  //   }

  //   for (const cookie of cookies) {
  //     console.log(`cookie: ${cookie}`);
  //   }

  //   if (!includesString("__Secure-next-auth.session-token", cookies)) {
  //     throw new Error("Missing session token");
  //   }

  //   headers['Cookie'] = cookies;
    
  //   await delay(randomMilliseconds(1250, 3350));
  //   await (new HttpBuilder(this._httpClient)
  //     .setHostname("chat.openai.com")
  //     .setPath("/api/auth/session")
  //     .setHeaders(headers)
  //     .setMethod("GET")
  //     .build())
  //   .request(async (req, res) => {

  //     let data = '';

  //     let nextCookies = res.headers['set-cookie'] ?? [];
  //     nextCookies = nextCookies.concat(cookies ?? []);

  //     res.setEncoding('utf8');

  //     res.on('data', (chunk) => {
  //       data += chunk;
  //     });

  //     res.on('end', async () => {
  //       console.log("apiAuthSessionToken");
  //       console.log(`statusCode: ${res.statusCode}`);
  //       console.log(`statusMessage: ${res.statusMessage}`);
  //       console.log(`${JSON.stringify(res.headers)}`);
  //       console.log(`${JSON.stringify(req.getHeaders())}`);
  //       console.log(`nextCookies: ${nextCookies}`);
  //       if (res.statusCode === 200 && res.statusMessage === "OK") {
  //         const authSessionJson = JSON.parse(data);
  //         authSessionJson['expires'] = new Date(authSessionJson['expires']);
  //         this._authSessionJsonData = authSessionJson;
  //         this._cookies = nextCookies;
  //         console.log(this._authSessionJsonData);
  //       }
  //     });
  //   });
  // }

  // async apiConversation(conversationId: string, prompt: string, callback?: (data: string) => Promise<void> | void) {
  //   if (this._authSessionJsonData === undefined) {
  //     throw new Error("Missing auth session data");
  //   }

  //   if (this._cookies === undefined || this._cookies.length === 0) {
  //     throw new Error("Missing auth cookies");
  //   }

  //   const conversationPayload = {
  //     "action": "next",
  //     "conversation_id": conversationId,
  //     "messages": [
  //       {
  //         "content": {
  //           "content_type": "text",
  //           "parts": [
  //             prompt
  //           ]
  //         },
  //         "id": randomUUID(),
  //         "role": "user",
  //       }
  //     ],
  //     "model": "text-davinci-002-render",
  //     "parent_message_id": randomUUID(),
  //   };

  //   const headers: OutgoingHttpHeaders = {
  //     "Authorization": `Bearer ${this._authSessionJsonData.accessToken}`,
  //     "Accept": "text/event-stream",
  //     "Accept-Encoding": "gzip, deflate, br",
  //     "Accept-Language": "en-CA,en-US;q=0.7,en;q=0.3",
  //     "Cache-Control": "no-cache",
  //     "Connection": "keep-alive",
  //     "Content-Length": JSON.stringify(conversationPayload).length,
  //     "Content-Type": "application/json",
  //     "Referer": "https://chat.openai.com/chat",
  //     "Origin": "https://chat.openai.com",
  //     "Sec-Fetch-Dest": "empty",
  //     "Sec-Fetch-Mode": "cors",
  //     "Sec-Fetch-Site": "same-origin",
  //     "Sec-GPC": 1,
  //     "Pragma": "no-cache",
  //     "TE": "trailers",
  //     "Cookie": this._cookies,
  //   }

  //   await delay(randomMilliseconds(1250, 3350));
  //   await (new HttpBuilder(this._httpClient)
  //     .setHostname("chat.openai.com")
  //     .setPath("/backend-api/conversation")
  //     .setHeaders(headers)
  //     .setMethod("POST")
  //     .build())
  //   .request(async (req, res) => {
  //     let data = '';

  //     res.setEncoding('utf8');

  //     res.on('data', (chunk) => {
  //       data += chunk;
  //     });

  //     res.on('end', async () => {
  //       console.log(`data: ${data}`);
  //       console.log(`statusCode: ${res.statusCode}`);
  //       console.log(`statusMessage: ${res.statusMessage}`);
  //     });
  //   }, JSON.stringify(conversationPayload));
  // }
}

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const randomMilliseconds = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1) + min);



const encodeFormData = (formData: Map<string, string>): string => {
  let urlencodedString = "";
  for (const [key, value] of formData) {
    urlencodedString += `${encodeURIComponent(key)}=${encodeURIComponent(value)}&`; 
  }
  urlencodedString = urlencodedString.slice(0, urlencodedString.length-1);
  return urlencodedString;
}

const includesString = (str: string, substrings: string[]): boolean => {
  for (const substring of substrings) {
    if (substring.includes(str)) {
      return true;
    }
  }
  return false;
}

const main = async () => {


  const chatgptAuth = new ChatGPTAuth(
    "akarapinrar@gmail.com",
    "tbi8GJYfibLPkW",
  );

  const conversationId = randomUUID();
  const prompt: string = "Explain the concept of a neural network with as much technical detail as possible.";
  // chatgptAuth.apiConversation(conversationId, prompt);
  
  console.log("Logging in...");
  await chatgptAuth.login();
  
  // console.log("Make a request to Backend API Conversation endpoint...");
  // await chatgptAuth.apiConversation(conversationId, prompt, async (data: string) => {
  //   console.log(data);
  //   console.log("OpenAI ChatGPT Conversation Endpoint worked!");
  // });
}


(async () => {
  try { 
    const _req = await main();
  } catch (e) {
    throw e;
  }
})();

