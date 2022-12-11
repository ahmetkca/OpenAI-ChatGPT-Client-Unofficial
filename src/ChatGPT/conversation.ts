import { PipelineStep, Pipeline } from "../utils/pipeline"
import * as https from "node:https";
import { IncomingMessage, OutgoingHttpHeaders } from "node:http";
import { chatgptHeaders, chatgptReqOpts } from "./chatgptApiRequestInfo";
import { IAuthSessionJsonResponse } from "../authFlowRequests/concreteAuthSteps";
import { randomUUID } from "node:crypto";
import { fetch, IFetchParams, /*fetchEventStream*/ } from "../utils/fetch";


abstract class ChatGPTApiStep<I, O> extends PipelineStep<I, O> {
    protected readonly httpAgent: https.Agent;
    protected readonly userAgent: string;
    protected readonly reqOpts: https.RequestOptions;
    protected readonly reqHeaders: OutgoingHttpHeaders;

    /**
     * The ID of the auth step.
     * This is used to look up the request options and headers for the step.
     */
     static readonly chatgptStepId: string;

    constructor({ httpAgent, chatgptStepId, userAgent }: { httpAgent: https.Agent, chatgptStepId: string, userAgent: string }) {
        super();
        this.httpAgent = httpAgent;
        this.userAgent = userAgent;

        if (!chatgptStepId) {
            throw new Error('Auth step ID not set');
        }

        if (!chatgptReqOpts.has(chatgptStepId)) {
            throw new Error(`No request options found for auth step ID ${chatgptStepId}`);
        }
        if (!chatgptHeaders.has(chatgptStepId)) {
            throw new Error(`No request headers found for auth step ID ${chatgptStepId}`);
        }
        this.reqOpts = chatgptReqOpts.get(chatgptStepId) as https.RequestOptions;
        this.reqHeaders = chatgptHeaders.get(chatgptStepId) as OutgoingHttpHeaders;
        if (!this.reqOpts || !this.reqHeaders) {
            throw new Error(`Invalid auth step ID: ${chatgptStepId}`);
        }
        this.reqHeaders['User-Agent'] = userAgent;
        this.reqOpts.headers = this.reqHeaders;
        this.reqOpts.agent = this.httpAgent;
    }

    protected async fetch({
        options,
        payload,
        encoding = 'utf-8',
        onData,
    }: Partial<IFetchParams>): Promise<[IncomingMessage, string]> {
        if (!options) {
            // console.debug(`No options provided for fetch, using default options for auth step ${this.constructor.name}`);
            options = this.reqOpts;
        }

        // console.debug(`fetching ${options.method} ${options.hostname}${options.path}${options.port ? `:${options.port}` : ''}`);

        return fetch({
            options: { ...options },
            payload,
            encoding,
            onData,
        });
    }
}

interface IConversationStepInput {
    conversationId?: string;
    promptMessage?: string;
    messageId?: string;
    parentMessageId?: string;
};

interface IConversationStepOutput {
  messageId: string; // this is the message id of the response from chatgpt ai api (this is used as a parent_message_id for the next conversation)
  conversationId: string; // this is the conversation id of the response from chatgpt ai api (this is used as a conversation_id for the next conversation)
  responseMessageFromChatGPT: string; // this is the response message from chatgpt ai api
};


interface IConversationConstructorParams {
  httpAgent: https.Agent;
  userAgent: string;
  cookies: string[];
  authSession: IAuthSessionJsonResponse;
}

interface IConversationRequestPayload {
    action: string;
    conversation_id?: string;
    messages: {
        content: {
            content_type: string;
            parts: string[];
        };
        id: string;
        role: string;
    }[];
    model: string;
    parent_message_id?: string;
}

interface IConversationRequestResponse {
    message: {
        id: string;
        role: string;
        user: any;
        create_time: any;
        update_time: any;
        content: {
            content_type: string;
            parts: string[];
        };
        end_turn: any;
        weight: number;
        metadata: any;
    };
    conversation_id: string;
    error: any;
}


export class Conversation extends ChatGPTApiStep<IConversationStepInput, IConversationStepOutput> {

    static override readonly chatgptStepId: string = 'conversation';

    private cookies: string[];
    private authSession: IAuthSessionJsonResponse;

    constructor({ 
      httpAgent, 
      userAgent, 
      cookies, 
      authSession 
    }: IConversationConstructorParams) 
    {
        super({ httpAgent, chatgptStepId: Conversation.chatgptStepId, userAgent });
        this.cookies = cookies;
        this.authSession = authSession;
    }



    async process(): Promise<IConversationStepOutput> {
        if (!this.input) {
            throw new Error('No input provided');
        }
        
        const { conversationId, promptMessage, messageId } = this.input;
        let { parentMessageId } = this.input;
        
        // Possibly this is the first message in the conversation
        // response of the first request will have the conversationId and messageId (which will be supplied as parentMessageId for the next request)
        if (!parentMessageId && !conversationId) {
            // console.warn('No conversationId or parentMessageId provided. Creating new conversation');
            parentMessageId = randomUUID();
        }

        if (!messageId) {
            throw new Error('No messageId provided');
        }

        if (!promptMessage) {
            throw new Error('No promptMessage provided');
        }

        const payload: IConversationRequestPayload = {
            action: 'next',
            messages: [{
                content:{
                    content_type: 'text',
                    parts: [promptMessage]
                },
                id: messageId,
                role: 'user',
            }],
            model: 'text-davinci-002-render',
            parent_message_id: parentMessageId,
        };
        if (conversationId) {
            payload.conversation_id = conversationId;
        }

        this.reqHeaders['Cookie'] = this.cookies;
        this.reqHeaders['Authorization'] = `Bearer ${this.authSession.accessToken}`;
        this.reqHeaders['Content-Length'] = JSON.stringify(payload).length;
        this.reqOpts.headers = this.reqHeaders;

        let toBeParsed: string = '';

        const [res, data] = await this.fetch({
            payload: JSON.stringify(payload),
            onData: (chunk: string, reject) => {
                // Event Stream is done
                if (chunk.startsWith('data: ') && chunk.endsWith('\n\n') && chunk.slice("data: ".length, -2).trim() === '[DONE]') {
                    return;
                }
                // data chunk fully sent
                if (chunk.startsWith('data: ') && chunk.endsWith('\n\n')) {
                    toBeParsed = chunk.slice("data: ".length).trim();
                    // console.debug(JSON.parse(toBeParsed).message.content.parts[0]?.split(' ')?.at(-1));
                    return;
                }
                // first partially sent data chunk
                if (chunk.startsWith('data: ') && !chunk.endsWith('\n\n')) {
                    toBeParsed = chunk.slice("data: ".length).trim();
                    return;
                }
                // data chunk partially sent
                if (!chunk.startsWith('data: ') && !chunk.endsWith('\n\n')) {
                    toBeParsed += chunk;
                    return;
                }
                // last partially sent data chunk
                if (!chunk.startsWith('data: ') && chunk.endsWith('\n\n')) {
                    toBeParsed += chunk.slice(0, chunk.length - "\n\n".length);
                    return;
                }
            },
            encoding: 'utf-8',
        });

        if (res.statusCode !== 200 && res.statusMessage !== 'OK') {
            console.log(data)
            throw new Error("Error while fetching conversation: " + res.statusCode + " " + res.statusMessage);
        }
        
        let responseData: IConversationRequestResponse | undefined;
        try {
            responseData = JSON.parse(toBeParsed);
            if (!responseData) {
                throw new Error('No response data');
            }
        } catch (e) {
            console.log(toBeParsed);
            throw new Error("Error while parsing conversation response: " + e);
        }

        if (responseData.error) {
            throw new Error("Error while fetching conversation: " + responseData.error);
        }

        const responseMessageFromChatGPT = responseData.message.content.parts[0];

        if (!responseMessageFromChatGPT) {
            throw new Error("Error while fetching conversation: No response message from chatgpt");
        }

        const output = {
            conversationId: responseData.conversation_id,
            messageId: responseData.message.id,
            responseMessageFromChatGPT,
        }
        this.output = output;

        return this.output;
    }

    setMessage(message: string): void {
        this.input = {
            ...this.input,
            promptMessage: message,
        };
    }
}


export class ConversationPipeline extends Pipeline<
    IConversationStepInput, 
    IConversationStepOutput, 
    IConversationStepInput, 
    IConversationStepOutput
> {
    private lastConversationId?: string;
    private lastParentMessageId?: string;
    private lastMessageFromBot?: string;

    resetConversation(): void {
        this.lastConversationId = undefined;
        this.lastParentMessageId = undefined;
        this.lastMessageFromBot = undefined;
        this.deleteLastConversation();
        this.clear();
    }

    // Since this is a special type of pipeline
    // it expects the steps to be of type Conversation
    // and at any point it can only have one conversation step
    override async run(): Promise<void> {
        if (this.lastConversationId) {
            // console.debug('You are continuing a conversation');
        } else {
            // console.debug('You are starting a new conversation');
        }
        if (this.steps.length > 1) {
            throw new Error('ConversationPipeline can only have one conversation step');
        }
        if (this.steps.length === 0) {
            throw new Error('ConversationPipeline has no conversation step');
        }
        if (!this.steps[0]) {
            throw new Error('ConversationPipeline has no conversation step');
        }
        const conversationStep = this.steps[0];
        conversationStep.input = {
            ...conversationStep.input,
            conversationId: this.lastConversationId,
            messageId: randomUUID(),
            parentMessageId: this.lastParentMessageId,
        };
        const output = await conversationStep.process();
        this.lastConversationId = output.conversationId;
        this.lastParentMessageId = output.messageId;
        this.lastMessageFromBot = output.responseMessageFromChatGPT;
        this.clear();
    }

    // no op if there is no conversation step
    deleteLastConversation(): void {
        if (this.steps.length > 0) {
            this.steps = this.steps.slice(0, this.steps.length - 1);
        }
    }


    
}
