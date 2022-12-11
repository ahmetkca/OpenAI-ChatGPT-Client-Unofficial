import { IncomingMessage } from 'node:http';
import * as https from 'node:https';

interface IFetchParams {
    options: https.RequestOptions;
    payload?: string;
    encoding?: BufferEncoding;
    onData?: (chunk: string, reject: (reason?: any) => void) => void;
}

const fetch = ({
    options,
    payload,
    encoding = 'utf-8',
    onData,
}: IFetchParams): Promise<[IncomingMessage, string]> => new Promise((resolve, reject) => {
    // console.debug(`fetching ${options.method} ${options.hostname}${options.path}`);
    const req = https.request({
        ...options,
        timeout: 10000,
    }, (res) => {
        let data: string = "";
        res.setEncoding(encoding);
        res.on('data', (chunk) => {
            data += chunk;
            if (onData) onData(chunk, reject);
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

type TFetchReturn = ReturnType<typeof fetch>;

export { fetch, TFetchReturn, IFetchParams };
