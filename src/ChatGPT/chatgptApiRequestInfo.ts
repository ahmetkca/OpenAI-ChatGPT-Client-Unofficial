import { OutgoingHttpHeaders } from "http";
import { RequestOptions } from "https";

const chatgptReqOpts: Map<string, RequestOptions> = new Map();
const chatgptHeaders: Map<string, OutgoingHttpHeaders> = new Map();


chatgptReqOpts.set('conversation', {
    hostname: "chat.openai.com",
    path: "/backend-api/conversation",
    method: "POST",
});

chatgptHeaders.set('conversation', {
    "Accept": "text/event-stream",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-CA,en-US;q=0.7,en;q=0.3",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Content-Type": "application/json",
    "Referer": "https://chat.openai.com/chat",
    "Origin": "https://chat.openai.com",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Sec-GPC": 1,
    "Pragma": "no-cache",
    "TE": "trailers",
});

export { chatgptReqOpts, chatgptHeaders };