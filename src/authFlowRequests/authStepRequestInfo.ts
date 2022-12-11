import { OutgoingHttpHeaders } from "node:http";
import { RequestOptions } from "node:https";

// Request options and headers for the auth flow steps
const authStepReqOpts: Map<string, RequestOptions> = new Map();
const authStepHeaders: Map<string, OutgoingHttpHeaders> = new Map();

// Request information for the first step in the auth flow
// This is the request that begins the auth flow
authStepReqOpts.set('authLoginBegins', {
    hostname: 'chat.openai.com',
    path: '/auth/login',
    method: 'GET',
});
authStepHeaders.set('authLoginBegins', {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
});


// Request information for the second step in the auth flow
// This is the request that gets the CSRF token
authStepReqOpts.set('getCsrfToken', {
    hostname: 'chat.openai.com',
    path: '/api/auth/csrf',
    method: 'GET',
});
authStepHeaders.set('getCsrfToken', {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "referer": "https://chat.openai.com/auth/login",
    "sec-ch-ua-platform": "Windows",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
});


// Request information for the third step in the auth flow
// Get Auth Url for authorization
authStepReqOpts.set('getAuthUrl', {
    hostname: 'chat.openai.com',
    path: '/api/auth/signin/auth0?prompt=login',
    method: 'POST',
});
authStepHeaders.set('getAuthUrl', {
    "Content-Type": "application/x-www-form-urlencoded",
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
    "referer": "https://chat.openai.com/auth/login",
    "Origin": "https://chat.openai.com",
    "Authority": "chat.openai.com",
    "sec-ch-ua-platform": "Windows",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
});

// Request information for the fourth step in the auth flow
// Authorize by provided auth url and get the redirect url
authStepReqOpts.set('authorizeByAuthUrl', {
    method: 'GET',
});
authStepHeaders.set('authorizeByAuthUrl', {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-CA,en-US;q=0.7,en;q=0.3",
    "Connection": "keep-alive",
    "referer": "https://chat.openai.com/",
    "upgrade-insecure-requests": 1,
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-site",
    "sec-fetch-user": "?1",
    "sec-gpc": 1,
    "te": "trailers",
})


// Request information for the fifth step in the auth flow
// Pre Login Identifier, Get potential cookies for next auth flow step.
authStepReqOpts.set('preLoginIdentifier', {
    method: 'GET',
});
authStepHeaders.set('preLoginIdentifier', {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-CA,en-US;q=0.7,en;q=0.3",
    "Connection": "keep-alive",
    "referer": "https://chat.openai.com/",
    "upgrade-insecure-requests": 1,
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-site",
    "sec-fetch-user": "?1",
    "sec-gpc": 1,
    "te": "trailers",
});


// Request information for the sixth step in the auth flow
authStepReqOpts.set('loginIdentifierByEmail', {
    method: 'POST',
});
authStepHeaders.set('loginIdentifierByEmail', {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-CA,en-US;q=0.7,en;q=0.3",
    "accept-encoding": "gzip, deflate, br",
    "content-type": "application/x-www-form-urlencoded",
    "origin": "https://auth0.openai.com",
    "upgrade-insecure-requests": 1,
    "Connection": "keep-alive",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "sec-gpc": 1,
    "te": "trailers",
});


// Request information for the seventh step in the auth flow
authStepReqOpts.set('preLoginPassword', {
    method: 'GET',
});
authStepHeaders.set('preLoginPassword', {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-CA,en-US;q=0.7,en;q=0.3",
    "accept-encoding": "gzip, deflate, br",
    "upgrade-insecure-requests": 1,
    "Connection": "keep-alive",
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "sec-gpc": 1,
    "te": "trailers",
});


// Request information for the eighth step in the auth flow
authStepReqOpts.set('loginPassword', {
    method: 'POST',
});
authStepHeaders.set('loginPassword', {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-CA,en-US;q=0.7,en;q=0.3",
    "accept-encoding": "gzip, deflate, br",
    "content-type": "application/x-www-form-urlencoded",
    "Connection": "keep-alive",
    "origin": "https://auth0.openai.com",
    "upgrade-insecure-requests": 1,
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "sec-gpc": 1,
    "te": "trailers",
});


// Request information for the ninth step in the auth flow
authStepReqOpts.set('authorizeResume', {
    method: 'GET',
});
authStepHeaders.set('authorizeResume', {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-CA,en-US;q=0.7,en;q=0.3",
    "accept-encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "upgrade-insecure-requests": 1,
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "sec-gpc": 1,
    "te": "trailers",
});


// Request information for the tenth step in the auth flow
authStepReqOpts.set('authCallback', {
    method: 'GET',
});
authStepHeaders.set('authCallback', {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "accept-language": "en-CA,en-US;q=0.7,en;q=0.3",
    "accept-encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "upgrade-insecure-requests": 1,
    "sec-fetch-dest": "document",
    "sec-fetch-mode": "navigate",
    "sec-fetch-site": "same-origin",
    "sec-fetch-user": "?1",
    "sec-gpc": 1,
    "te": "trailers",
});


// Request information for the eleventh step in the auth flow
authStepReqOpts.set('getAPIAuthSessionToken', {
    hostname: "chat.openai.com",
    path: "/api/auth/session",
    method: 'GET',
});
authStepHeaders.set('getAPIAuthSessionToken', {
    "Host": "chat.openai.com",
    "Accept": "*/*",
    "Accept-Language": "en-CA,en-US;q=0.7,en;q=0.3",
    "Accept-Encoding": "gzip, deflate, br",
    "Referer": "https://chat.openai.com/chat",
    "Connection": "keep-alive",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Sec-GPC": 1,
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
});


export { authStepReqOpts, authStepHeaders };
