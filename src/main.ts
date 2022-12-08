import { IncomingMessage } from 'node:http';
import * as https from 'node:https';


const fetch = (options: https.RequestOptions, payload?: string, encoding: BufferEncoding = 'utf-8'): Promise<[IncomingMessage, string]> => new Promise((resolve, reject) => {
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

interface IPipelineStep<I, O> {
    input?: I;
    output?: O;

    process(): Promise<O>;

    setInput(input: I): void;

    getInput(): I | undefined;

    getOutput(): O | undefined;
};

abstract class PipelineStep<I, O> implements IPipelineStep<I, O> {
    input?: I;
    output?: O;

    constructor(input?: I) {
        this.input = input;
    }

    abstract process(): Promise<O>;

    setInput(input: I): void {
        this.input = input;
    }

    getInput(): I | undefined {
        return this.input;
    }

    getOutput(): O | undefined {
        return this.output;
    }
}

abstract class AuthFlowStep<I, O> extends PipelineStep<I, O> {
    protected readonly httpAgent: https.Agent;
    
    constructor(httpAgent: https.Agent, input?: I) {
        super(input);
        this.httpAgent = httpAgent;
    }

    protected async fetch(options: https.RequestOptions, payload?: string, encoding: BufferEncoding = 'utf-8'): Promise<[IncomingMessage, string]> {
        return fetch({
            ...options,
            agent: this.httpAgent,
        }, payload, encoding);
    }
}


/**
 *  Proccesses the given list of steps in order.
 * The output of one step is the input of the next step.
 * That is why the order of the steps are important.
 */
class Pipeline {
    private isSuccessfull: boolean = false;
    private steps: IPipelineStep<any, any>[] = [];

    addStep(step: IPipelineStep<any, any>): void {
        this.steps.push(step);
    }

    setInitialInput(input: any): void {
        this.steps[0]?.setInput(input);
    }

    async run(): Promise<void> {
        let useItForNextStep: any = this.steps[0]?.getInput(); 
        for (const step of this.steps) {
            step.setInput(useItForNextStep);
            const output = await step.process();
            useItForNextStep = output;
        }
    }

    getLastStepOutput(): any {
        return this.steps[this.steps.length - 1]?.getOutput();
    }
}

class AuthLoginBegins extends AuthFlowStep<void, {cookies?: string[]}> {

    async process(): Promise<{cookies?: string[]}> {
        const [res, data] = await fetch({
            hostname: 'auth.example.com',
            path: '/login/begin',
            method: 'POST',
        });
        if (res.statusCode !== 200) {
            throw new Error(`Unexpected status code ${res.statusCode}`);
        }
        return {
            cookies: res.headers['set-cookie'],
        };
    }
}

class GetCsrfToken extends AuthFlowStep<{cookies: string[]}, { csrfToken: string, cookies?: string[]}> {

    async process(): Promise<{ csrfToken: string, cookies?: string[]}> {
        if (!this.input) {
            throw new Error('No input');
        }

        const [res, data] = await this.fetch({
            hostname: 'auth.example.com',
            path: '/login/begin',
            method: 'POST',
        });
        if (res.statusCode !== 200) {
            throw new Error(`Unexpected status code ${res.statusCode}`);
        }
        return {
            csrfToken: JSON.parse(data).csrfToken,
            cookies: res.headers['set-cookie'],
        };
    }
}

const main = async () => {
    const httpAgent = new https.Agent({
      keepAlive: true,
      maxSockets: 1,
      maxFreeSockets: 1,
    }); 
    
    const pipeline = new Pipeline();
    pipeline.addStep(new AuthLoginBegins(httpAgent));
    pipeline.addStep(new GetCsrfToken(httpAgent));
    await pipeline.run();

    console.log(pipeline.getLastStepOutput());
}

(async () => {
    await main();
})();
